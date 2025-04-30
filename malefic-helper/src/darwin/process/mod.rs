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
pub const NGROUPS_MAX: libc::c_int = 16;
pub const NGROUPS: libc::c_int = NGROUPS_MAX;

pub const WMESGLEN: libc::c_int = 7;

pub const COMAPT_MAXLOGNAME: libc::c_int = 12;

#[allow(non_camel_case_types)]
pub type caddr_t = *mut libc::c_void;

#[allow(non_camel_case_types)]
pub type segsz_t = i32;

#[allow(non_camel_case_types)]
pub type fixpt_t = u32;

#[allow(non_camel_case_types)]
pub type u_quad_t = u64;

// 结构体定义
#[repr(C)]
#[derive(Copy, Clone)]
pub struct kinfo_proc {
    pub kp_proc: extern_proc,
    pub kp_eproc: eproc,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct _pcred {
    /// Opaque content.
    pub pc_lock: [libc::c_char; 72],
    /// Current credentials.
    pub pc_ucred: *mut libc::c_void,
    /// Real user identifier.
    pub p_ruid: libc::uid_t,
    /// Saved effective user identifier.
    pub p_svuid: libc::uid_t,
    /// Real group identifier.
    pub p_rgid: libc::gid_t,
    /// Saved effective group identifier.
    pub p_svgid: libc::gid_t,
    /// Reference count.
    pub p_refcnt: libc::c_int,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct vmspace {
    // `dummy*` is literally what is used in the original header.
    pub dummy: i32,
    pub dummy2: caddr_t,
    pub dummy3: [i32; 5],
    pub dummy4: [caddr_t; 3],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct _ucred {
    /// Reference count.
    pub cr_ref: i32,
    /// Effective user identifier.
    pub cr_uid: libc::uid_t,
    /// Group count.
    pub cr_ngroups: libc::c_short,
    /// Group identifiers.
    pub cr_groups: [libc::gid_t; NGROUPS as usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct eproc {
    /// Process address.
    pub e_paddr: *mut libc::c_void,
    /// Session pointer.
    pub e_sess: *mut libc::c_void,
    /// Process credentials.
    pub e_pcred: _pcred,
    /// Current credentials.
    pub e_ucred: _ucred,
    /// Address space.
    pub e_vm: vmspace,
    /// Parent process identifier.
    pub e_ppid: libc::pid_t,
    /// Process group identifier.
    pub e_pgid: libc::pid_t,
    /// Job control counter.
    pub e_jobc: libc::c_short,
    /// Controlling TTY device identifier.
    pub e_tdev: libc::dev_t,
    /// Controlling TTY process group identifier.
    pub e_tpgid: libc::pid_t,
    /// Controlling TTY session pointer.
    pub e_tsess: *mut libc::c_void,
    /// Waiting channel message.
    pub e_wmesg: [libc::c_char; WMESGLEN as usize + 1],
    /// Text size.
    pub e_xsize: segsz_t,
    /// Text resident set size.
    pub e_xrssize: libc::c_short,
    /// Text reference count.
    pub e_xccount: libc::c_short,
    pub e_xswrss: libc::c_short,
    pub e_flag: i32,
    pub e_login: [libc::c_char; COMAPT_MAXLOGNAME as usize],
    pub e_spare: [i32; 4],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct __c_anonymous_p_st1 {
    pub __p_forw: *mut libc::c_void,
    pub __p_back: *mut libc::c_void,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub union __c_anonymous_p_un {
    pub p_st1: __c_anonymous_p_st1,
    pub __p_starttime: libc::timeval,
}

#[derive(Clone, Copy)]
    #[repr(C)]
    pub struct extern_proc {
        pub p_un: __c_anonymous_p_un,
        pub p_vmspace: *mut vmspace,
        pub p_sigacts: *mut libc::c_void,
        pub p_flag: libc::c_int,
        pub p_stat: libc::c_char,
        pub p_pid: libc::pid_t,
        pub p_oppid: libc::pid_t,
        pub p_dupfd: libc::c_int,
        pub user_stack: caddr_t,
        pub exit_thread: *mut libc::c_void,
        pub p_debugger: libc::c_int,
        pub sigwait: libc::boolean_t,
        pub p_estcpu: libc::c_uint,
        pub p_cpticks: libc::c_int,
        pub p_pctcpu: fixpt_t,
        pub p_wchan: *mut libc::c_void,
        pub p_wmesg: *mut libc::c_char,
        pub p_swtime: libc::c_uint,
        pub p_slptime: libc::c_uint,
        pub p_realtimer: libc::itimerval,
        pub p_rtime: libc::timeval,
        pub p_uticks: u_quad_t,
        pub p_sticks: u_quad_t,
        pub p_iticks: u_quad_t,
        pub p_traceflag: libc::c_int,
        pub p_tracep: *mut libc::c_void,
        pub p_siglist: libc::c_int,
        pub p_textvp: *mut libc::c_void,
        pub p_holdcnt: libc::c_int,
        pub p_sigmask: libc::sigset_t,
        pub p_sigignore: libc::sigset_t,
        pub p_sigcatch: libc::sigset_t,
        pub p_priority: libc::c_uchar,
        pub p_usrpri: libc::c_uchar,
        pub p_nice: libc::c_char,
        pub p_comm: [libc::c_char; libc::MAXCOMLEN + 1],
        pub p_pgrp: *mut libc::c_void,
        pub p_addr: *mut libc::c_void,
        pub p_xstat: libc::c_ushort,
        pub p_acflag: libc::c_ushort,
        pub p_ru: *mut libc::c_void,
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
            mib.len() as _,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ).eq(&-1)
        {
            return Err(anyhow::anyhow!("Failed to get process info"));
        }

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
            mib.len() as _,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ).eq(&-1) {
            return Err(anyhow::anyhow!("Failed to get process architecture"));
        }

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
