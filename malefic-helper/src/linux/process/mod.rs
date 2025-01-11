use crate::common::process::Process;
use nix::unistd::{Uid, User};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;

pub fn get_processes() -> anyhow::Result<HashMap<u32, Process>> {
    let mut processes = HashMap::new();

    // 遍历 /proc 目录
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let path = entry.path();

        // 只处理数字命名的目录（进程ID）
        if let Some(pid_str) = path.file_name().and_then(|s| s.to_str()) {
            if let Ok(pid) = pid_str.parse::<u32>() {
                if let Ok(process) = get_process_info(pid) {
                    processes.insert(pid, process);
                }
            }
        }
    }

    Ok(processes)
}

pub fn get_current_pid() -> u32 {
    unsafe { libc::getpid() as u32 }
}

pub fn get_parent_pid() -> anyhow::Result<u32> {
    unsafe { Ok(libc::getppid() as u32) }
}

pub fn get_current_process_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_default()
}

pub fn get_process_info(pid: u32) -> anyhow::Result<Process> {
    let proc_path = Path::new("/proc").join(pid.to_string());

    // 读取 /proc/[pid]/stat 文件获取基本信息
    let stat = fs::read_to_string(proc_path.join("stat"))?;
    let stat_parts: Vec<&str> = stat.split_whitespace().collect();

    // 获取进程名（去掉括号）
    let name = stat_parts[1]
        .trim_start_matches('(')
        .trim_end_matches(')')
        .to_string();

    // 获取父进程ID
    let ppid = stat_parts[3].parse::<u32>()?;

    // 读取 /proc/[pid]/status 文件获取 UID
    let status = fs::read_to_string(proc_path.join("status"))?;
    let uid = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("0")
        .to_string();

    // 读取 /proc/[pid]/exe 链接获取可执行文件路径
    let path = fs::read_link(proc_path.join("exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    // 读取 /proc/[pid]/cmdline 获取命令行参数
    let mut cmdline = String::new();
    if let Ok(mut file) = fs::File::open(proc_path.join("cmdline")) {
        let mut buffer = Vec::new();
        if file.read_to_end(&mut buffer).is_ok() {
            cmdline = buffer
                .split(|&b| b == 0)
                .filter_map(|s| String::from_utf8(s.to_vec()).ok())
                .collect::<Vec<_>>()
                .join(" ");
        }
    }

    // 获取架构信息
    let arch = get_process_architecture(pid)?;

    // 获取所有者信息
    let owner = get_process_owner(&uid)?;

    Ok(Process {
        name,
        pid,
        ppid,
        arch,
        owner,
        path,
        args: cmdline,
    })
}

fn get_process_architecture(pid: u32) -> anyhow::Result<String> {
    // 读取进程的可执行文件
    let exe_path = format!("/proc/{}/exe", pid);
    let mut file = fs::File::open(exe_path)?;
    let mut buffer = [0u8; 5];
    file.read_exact(&mut buffer)?;

    // 检查ELF头部
    if buffer[0..4] != [0x7f, 0x45, 0x4c, 0x46] {
        return Ok("unknown".to_string());
    }

    // 检查是32位还是64位
    match buffer[4] {
        1 => Ok("x86".to_string()),
        2 => Ok("x64".to_string()),
        _ => Ok("unknown".to_string()),
    }
}

fn get_process_owner(uid: &str) -> anyhow::Result<String> {
    let uid = uid.parse::<u32>()?;
    let user =
        User::from_uid(Uid::from_raw(uid))?.ok_or_else(|| anyhow::anyhow!("User not found"))?;
    Ok(user.name)
}
