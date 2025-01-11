use crate::common::process::Process;
use libc::{
    c_char, c_int, c_short, c_void, gid_t, pid_t, proc_pidpath, sysctl, uid_t, CTL_KERN, KERN_PROC,
    KERN_PROC_ALL,
};
use nix::unistd::{Uid, User};
use std::collections::HashMap;
use std::ffi::CStr;
use std::mem;
use std::ptr;

// 常量定义
#[allow(non_camel_case_types)]
type proc_pidinfo_t = i32;
const PROC_PIDPATHINFO: i32 = 11;
const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;
const KERN_PROC_PID: i32 = 1;
const P_LP64: i32 = 0x4;

// 结构体定义
#[repr(C)]
#[derive(Copy, Clone)]
pub struct kinfo_proc {
    pub kp_proc: extern_proc,
    pub kp_eproc: eproc,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct extern_proc {
    pub p_un: *mut c_void,
    pub p_pid: pid_t,
    pub p_flag: c_int,
    pub p_comm: [c_char; 16],
    // ... 其他字段根据需要添加
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct eproc {
    pub e_paddr: *mut c_void,
    pub e_ppid: pid_t,
    pub e_pcred: pcred,
    pub e_ucred: ucred,
    // ... 其他字段根据需要添加
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcred {
    pub pc_lock: [c_char; 72],
    pub pc_ucred: *mut ucred,
    pub p_ruid: uid_t,
    pub p_svuid: uid_t,
    pub p_rgid: gid_t,
    pub p_svgid: gid_t,
    pub p_refcnt: c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ucred {
    pub cr_ref: c_int,
    pub cr_uid: uid_t,
    pub cr_ngroups: c_short,
    pub cr_groups: [gid_t; 16],
}

pub fn get_processes() -> anyhow::Result<HashMap<u32, Process>> {
    let mut processes = HashMap::new();
    unsafe {
        // 获取进程列表大小
        let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0];
        let mut size: usize = 0;
        if sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(anyhow::anyhow!("Failed to get process list size"));
        }

        // 分配缓冲区
        let count = size / mem::size_of::<kinfo_proc>();
        let mut proc_list = vec![mem::zeroed::<kinfo_proc>(); count];

        // 获取进程列表
        if sysctl(
            mib.as_mut_ptr(),
            3,
            proc_list.as_mut_ptr() as *mut c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(anyhow::anyhow!("Failed to get process list"));
        }

        // 处理每个进程
        for proc_info in proc_list.iter().take(count) {
            let pid = proc_info.kp_proc.p_pid as u32;
            if let Ok(process) = get_process_info(pid) {
                processes.insert(pid, process);
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
    unsafe {
        let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid as c_int];
        let mut proc_info: kinfo_proc = mem::zeroed();
        let mut size = mem::size_of::<kinfo_proc>();

        if sysctl(
            mib.as_mut_ptr(),
            4,
            &mut proc_info as *mut _ as *mut c_void,
            &mut size,
            ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(anyhow::anyhow!("Failed to get process info"));
        }

        // 获取进程名
        let name = CStr::from_ptr(proc_info.kp_proc.p_comm.as_ptr())
            .to_string_lossy()
            .into_owned();

        // 获取父进程ID
        let ppid = proc_info.kp_eproc.e_ppid as u32;

        // 获取进程路径
        let mut path_buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE as usize];
        let path_len = proc_pidpath(
            pid as pid_t,
            path_buf.as_mut_ptr() as *mut c_void,
            PROC_PIDPATHINFO_MAXSIZE as u32,
        );
        let path = if path_len > 0 {
            CStr::from_ptr(path_buf.as_ptr() as *const i8)
                .to_string_lossy()
                .into_owned()
        } else {
            String::new()
        };

        // 获取命令行参数
        let args = get_process_args(pid);

        // 获取架构信息
        let arch = get_process_architecture(pid)?;

        // 获取所有者信息
        let owner = get_process_owner(proc_info.kp_eproc.e_ucred.cr_uid)?;

        Ok(Process {
            name,
            pid,
            ppid,
            arch,
            owner,
            path,
            args,
        })
    }
}

fn get_process_args(pid: u32) -> String {
    unsafe {
        let mut mib = [CTL_KERN, libc::KERN_PROCARGS2, pid as c_int];
        let mut size: usize = 0;

        // 获取参数大小
        if sysctl(
            mib.as_mut_ptr(),
            3,
            ptr::null_mut(),
            &mut size,
            ptr::null_mut(),
            0,
        ) < 0
        {
            return String::new();
        }

        // 分配缓冲区
        let mut buffer = vec![0u8; size];
        if sysctl(
            mib.as_mut_ptr(),
            3,
            buffer.as_mut_ptr() as *mut c_void,
            &mut size,
            ptr::null_mut(),
            0,
        ) < 0
        {
            return String::new();
        }

        // 解析参数
        let mut args = Vec::new();
        let mut pos = mem::size_of::<c_int>();
        while pos < size {
            if let Some(end) = buffer[pos..].iter().position(|&b| b == 0) {
                if let Ok(arg) = String::from_utf8(buffer[pos..pos + end].to_vec()) {
                    if !arg.is_empty() {
                        args.push(arg);
                    }
                }
                pos += end + 1;
            } else {
                break;
            }
        }

        args.join(" ")
    }
}

fn get_process_architecture(pid: u32) -> anyhow::Result<String> {
    unsafe {
        let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid as c_int];
        let mut proc_info: kinfo_proc = mem::zeroed();
        let mut size = mem::size_of::<kinfo_proc>();

        if sysctl(
            mib.as_mut_ptr(),
            4,
            &mut proc_info as *mut _ as *mut c_void,
            &mut size,
            ptr::null_mut(),
            0,
        ) < 0
        {
            return Ok("unknown".to_string());
        }

        // 在 macOS 上，通过进程标志判断是否是 64 位进程
        if proc_info.kp_proc.p_flag & P_LP64 != 0 {
            Ok("x64".to_string())
        } else {
            Ok("x86".to_string())
        }
    }
}

fn get_process_owner(uid: u32) -> anyhow::Result<String> {
    let user =
        User::from_uid(Uid::from_raw(uid))?.ok_or_else(|| anyhow::anyhow!("User not found"))?;
    Ok(user.name)
}
