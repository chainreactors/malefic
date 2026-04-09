use crate::Process;
use libc::{
    c_char, c_int, c_short, c_void, gid_t, pid_t, proc_pidpath, sysctl, uid_t, CTL_KERN, KERN_PROC,
    KERN_PROC_ALL,
};
use nix::unistd::{Uid, User};
use std::collections::HashMap;
use std::ffi::CStr;
use std::mem;
use std::ptr;

const KERN_PROC_PID: i32 = 1;
const P_LP64: i32 = 0x4;
const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;
pub const NGROUPS: libc::c_int = 16;
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct kinfo_proc {
    pub kp_proc: extern_proc,
    pub kp_eproc: eproc,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct _pcred {
    pub pc_lock: [libc::c_char; 72],
    pub pc_ucred: *mut libc::c_void,
    pub p_ruid: libc::uid_t,
    pub p_svuid: libc::uid_t,
    pub p_rgid: libc::gid_t,
    pub p_svgid: libc::gid_t,
    pub p_refcnt: libc::c_int,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct vmspace {
    pub dummy: i32,
    pub dummy2: caddr_t,
    pub dummy3: [i32; 5],
    pub dummy4: [caddr_t; 3],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct _ucred {
    pub cr_ref: i32,
    pub cr_uid: libc::uid_t,
    pub cr_ngroups: libc::c_short,
    pub cr_groups: [libc::gid_t; NGROUPS as usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct eproc {
    pub e_paddr: *mut libc::c_void,
    pub e_sess: *mut libc::c_void,
    pub e_pcred: _pcred,
    pub e_ucred: _ucred,
    pub e_vm: vmspace,
    pub e_ppid: libc::pid_t,
    pub e_pgid: libc::pid_t,
    pub e_jobc: libc::c_short,
    pub e_tdev: libc::dev_t,
    pub e_tpgid: libc::pid_t,
    pub e_tsess: *mut libc::c_void,
    pub e_wmesg: [libc::c_char; WMESGLEN as usize + 1],
    pub e_xsize: segsz_t,
    pub e_xrssize: libc::c_short,
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

pub fn get_processes() -> anyhow::Result<HashMap<u32, Process>> {
    let mut processes = HashMap::new();
    unsafe {
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
        let count = size / mem::size_of::<kinfo_proc>();
        let mut proc_list = vec![mem::zeroed::<kinfo_proc>(); count];
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
        )
        .eq(&-1)
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

        let name = CStr::from_ptr(proc_info.kp_proc.p_comm.as_ptr())
            .to_string_lossy()
            .into_owned();
        let ppid = proc_info.kp_eproc.e_ppid as u32;

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

        let args = get_process_args(pid);
        let arch = get_process_architecture(pid)?;
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
        )
        .eq(&-1)
        {
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
