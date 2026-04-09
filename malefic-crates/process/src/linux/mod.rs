use crate::Process;
use nix::unistd::{Uid, User};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;

pub fn get_processes() -> anyhow::Result<HashMap<u32, Process>> {
    let mut processes = HashMap::new();
    for entry in fs::read_dir("/proc")?.flatten() {
        let path = entry.path();
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

pub fn get_process_info(pid: u32) -> anyhow::Result<Process> {
    let proc_path = Path::new("/proc").join(pid.to_string());

    let stat = fs::read_to_string(proc_path.join("stat"))?;

    // Process name is between first '(' and last ')' - handles names with spaces
    let name_start = stat
        .find('(')
        .ok_or_else(|| anyhow::anyhow!("invalid stat"))?
        + 1;
    let name_end = stat
        .rfind(')')
        .ok_or_else(|| anyhow::anyhow!("invalid stat"))?;
    let name = stat[name_start..name_end].to_string();

    // Fields after ')': state ppid pgrp session ...
    let rest = &stat[name_end + 2..];
    let rest_parts: Vec<&str> = rest.split_whitespace().collect();
    let ppid = rest_parts
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("invalid stat"))?
        .parse::<u32>()?;

    let status = fs::read_to_string(proc_path.join("status"))?;
    let uid = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("0")
        .to_string();

    let path = fs::read_link(proc_path.join("exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

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

    let arch = get_process_architecture(pid).unwrap_or_else(|_| "unknown".to_string());
    let owner = get_process_owner(&uid).unwrap_or_else(|_| uid.clone());

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
    let exe_path = format!("/proc/{}/exe", pid);
    let mut file = fs::File::open(exe_path)?;
    let mut buffer = [0u8; 5];
    file.read_exact(&mut buffer)?;

    if buffer[0..4] != [0x7f, 0x45, 0x4c, 0x46] {
        return Ok("unknown".to_string());
    }

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
