use std::ffi::c_void;
use std::ptr::null_mut;
use windows::core::{Error, Result, HRESULT, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, ImpersonateLoggedOnUser,
    LogonUserW, LookupAccountSidW, LookupPrivilegeDisplayNameW, LookupPrivilegeNameW,
    LookupPrivilegeValueW, RevertToSelf, SecurityImpersonation, TokenElevation,
    TokenIntegrityLevel, TokenPrivileges, TokenUser, LOGON32_LOGON_INTERACTIVE,
    LOGON32_PROVIDER_DEFAULT, LUID_AND_ATTRIBUTES,
    SE_PRIVILEGE_ENABLED, SID_NAME_USE, TOKEN_ACCESS_MASK,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY, TOKEN_TYPE,
};
use windows::Win32::System::Environment::{
    DestroyEnvironmentBlock, GetEnvironmentStringsW,
};
use windows::Win32::System::SystemServices::{
    SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_LOW_RID, SECURITY_MANDATORY_MEDIUM_RID,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, CreateProcessWithLogonW, GetCurrentProcessId, OpenProcess,
    OpenProcessToken, CREATE_NO_WINDOW, CREATE_PROCESS_LOGON_FLAGS, CREATE_UNICODE_ENVIRONMENT,
    PROCESS_CREATE_THREAD, PROCESS_CREATION_FLAGS, PROCESS_DUP_HANDLE, PROCESS_INFORMATION,
    PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE, STARTF_USESTDHANDLES, STARTUPINFOW, STARTUPINFOW_FLAGS,
};

use crate::win::common::{get_buffer, to_wide_string};
use crate::win::pipe::AnonymousPipe;

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
    let token_handle = get_token(
        unsafe { GetCurrentProcessId() },
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
    )?;

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
            return Err(Error::from(windows::core::HRESULT(1)));
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
            PROCESS_QUERY_INFORMATION
                | PROCESS_CREATE_THREAD
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE
                | PROCESS_DUP_HANDLE
                | PROCESS_TERMINATE,
            false,
            pid,
        )?;

        let mut token_handle: HANDLE = HANDLE::default();
        OpenProcessToken(
            process_handle,
            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
            &mut token_handle,
        )?;

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
            &mut process_info,
        )?;

        let _ = CloseHandle(process_info.hProcess);
        let _ = CloseHandle(process_info.hThread);
    }
    Ok(())
}

pub fn get_process_integrity_level(token_handle: HANDLE) -> Result<String> {
    let mut size_needed: u32 = 0;
    unsafe {
        let success =
            GetTokenInformation(token_handle, TokenIntegrityLevel, None, 0, &mut size_needed);
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
            rid if rid >= SECURITY_MANDATORY_MEDIUM_RID as u32
                && rid < SECURITY_MANDATORY_HIGH_RID as u32 =>
            {
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
        let mut display_name = vec![0u16; 256];
        let mut name_len = name.len() as u32;
        let mut display_name_len = display_name.len() as u32;
        let mut lang_id: u32 = 0;

        // 获取权限名称
        LookupPrivilegeNameW(
            PWSTR(null_mut()),
            &luid,
            PWSTR(name.as_mut_ptr()),
            &mut name_len,
        )?;

        // 获取权限显示名称
        LookupPrivilegeDisplayNameW(
            PWSTR(null_mut()),
            PWSTR(name.as_mut_ptr()),
            PWSTR(display_name.as_mut_ptr()),
            &mut display_name_len,
            &mut lang_id,
        )?;

        // 只返回实际使用的字符，去除空字符和未初始化的缓冲区
        let name_str = String::from_utf16_lossy(&name[..name_len as usize]);
        let display_name_str = String::from_utf16_lossy(&display_name[..display_name_len as usize]);

        Ok((name_str, display_name_str))
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


/// 以指定用户身份运行程序
///
/// # Arguments
///
/// * `username` - 用户名
/// * `domain` - 域名，如果是本地用户可以为空或"."
/// * `password` - 密码
/// * `program` - 要运行的程序路径
/// * `args` - 程序参数
/// * `use_network_credentials` - 是否仅用于网络凭据
/// * `load_user_profile` - 是否加载用户配置文件
/// * `inherit_env` - 是否继承当前环境变量
pub fn run_as(
    username: &str,
    domain: &str,
    password: &str,
    program: &str,
    args: &str,
    use_network_credentials: bool,
    load_user_profile: bool,
    inherit_env: bool,
) -> Result<String> {
    // 首先尝试启用必要的权限
    let _ = enable_privilege("SeAssignPrimaryTokenPrivilege");
    let _ = enable_privilege("SeImpersonatePrivilege");

    let mut logon_flags = CREATE_PROCESS_LOGON_FLAGS(0);
    let mut creation_flags = PROCESS_CREATION_FLAGS(CREATE_NO_WINDOW.0);
    let mut env_block: *mut c_void = std::ptr::null_mut();

    if use_network_credentials {
        logon_flags = CREATE_PROCESS_LOGON_FLAGS(logon_flags.0 | 0x00000002); // LOGON_NETCREDENTIALS_ONLY
    }

    if load_user_profile {
        logon_flags = CREATE_PROCESS_LOGON_FLAGS(logon_flags.0 | 0x00000001); // LOGON_WITH_PROFILE
    }

    if inherit_env {
        unsafe {
            // 获取当前环境变量
            env_block = GetEnvironmentStringsW().0.cast();
            if !env_block.is_null() {
                creation_flags |= CREATE_UNICODE_ENVIRONMENT;
            }
        }
    }

    let mut startup_info: STARTUPINFOW = STARTUPINFOW::default();
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    startup_info.dwFlags |= STARTF_USESTDHANDLES;
    startup_info.wShowWindow = 0; // SW_HIDE
    startup_info.dwFlags |= STARTUPINFOW_FLAGS(0x00000001); // STARTF_USESHOWWINDOW

    // 创建匿名管道用于捕获输出
    let pipe = AnonymousPipe::create()?;

    startup_info.hStdOutput = pipe.get_write_handle();
    startup_info.hStdError = pipe.get_write_handle();

    let mut process_info: PROCESS_INFORMATION = PROCESS_INFORMATION::default();

    let mut command = String::new();
    if !program.is_empty() {
        command.push_str(program);
        if !args.is_empty() {
            command.push_str(" ");
            command.push_str(args);
        }
    }

    let command_wide = to_wide_string(&command);
    let username_wide = to_wide_string(username);
    let domain_wide = to_wide_string(domain);
    let password_wide = to_wide_string(password);

    let mut output = String::new();

    unsafe {
        // 首先尝试使用CreateProcessAsUser
        let mut h_token = HANDLE::default();
        if LogonUserW(
            PWSTR(username_wide.as_ptr() as *mut u16),
            PWSTR(domain_wide.as_ptr() as *mut u16),
            PWSTR(password_wide.as_ptr() as *mut u16),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut h_token,
        )
        .is_ok()
        {
            let mut h_duptoken = HANDLE::default();
            if DuplicateTokenEx(
                h_token,
                TOKEN_ALL_ACCESS,
                None,
                SecurityImpersonation,
                TOKEN_TYPE(1), // TOKEN_PRIMARY
                &mut h_duptoken,
            )
            .is_ok()
            {
                // 尝试使用CreateProcessAsUser
                if CreateProcessAsUserW(
                    h_duptoken,
                    None,
                    PWSTR(command_wide.as_ptr() as *mut u16),
                    None,
                    None,
                    true,
                    creation_flags,
                    if !env_block.is_null() {
                        Some(env_block)
                    } else {
                        None
                    },
                    None,
                    &startup_info,
                    &mut process_info,
                )
                .is_ok()
                {
                    // 关闭写入端，这样当进程结束时读取端会收到EOF
                    let _ = CloseHandle(pipe.get_write_handle())?;

                    // 读取输出
                    output = pipe.read()?;

                    // 清理资源
                    if !env_block.is_null() {
                        let _ = DestroyEnvironmentBlock(env_block);
                    }
                    let _ = CloseHandle(h_duptoken)?;
                    let _ = CloseHandle(h_token)?;
                    let _ = CloseHandle(process_info.hProcess)?;
                    let _ = CloseHandle(process_info.hThread)?;
                    return Ok(output);
                }
                let _ = CloseHandle(h_duptoken)?;
            }
            let _ = CloseHandle(h_token)?;
        }

        // 如果CreateProcessAsUser失败，尝试使用CreateProcessWithLogonW
        if CreateProcessWithLogonW(
            PWSTR(username_wide.as_ptr() as *mut u16),
            PWSTR(domain_wide.as_ptr() as *mut u16),
            PWSTR(password_wide.as_ptr() as *mut u16),
            logon_flags,
            None,
            PWSTR(command_wide.as_ptr() as *mut u16),
            creation_flags,
            if !env_block.is_null() {
                Some(env_block)
            } else {
                None
            },
            None,
            &startup_info,
            &mut process_info,
        )
        .is_ok()
        {
            // 关闭写入端，这样当进程结束时读取端会收到EOF
            let _ = CloseHandle(pipe.get_write_handle())?;

            // 读取输出
            output = pipe.read()?;

            // 清理资源
            if !env_block.is_null() {
                let _ = DestroyEnvironmentBlock(env_block);
            }
            let _ = CloseHandle(process_info.hProcess)?;
            let _ = CloseHandle(process_info.hThread)?;
            return Ok(output);
        }

        // 如果所有尝试都失败，返回最后一个错误
        Err(Error::from_win32())
    }
}

pub fn get_system() -> Result<HANDLE> {
    get_system_token_duplication()
}

fn get_system_token_duplication() -> Result<HANDLE> {
    // 启用必要的权限
    if let Err(_) = enable_privilege("SeDebugPrivilege") {
        // 如果无法启用 SeDebugPrivilege，尝试继续
        println!("Warning: Could not enable SeDebugPrivilege");
    }
    if let Err(_) = enable_privilege("SeImpersonatePrivilege") {
        // 如果无法启用 SeImpersonatePrivilege，尝试继续
        println!("Warning: Could not enable SeImpersonatePrivilege");
    }

    // 获取所有进程
    let processes = crate::common::process::get_processes().map_err(|_| Error::from_win32())?;

    // 查找 SYSTEM 进程（按优先级排序）
    let system_process_names = [
        "winlogon.exe",
        "lsass.exe",
        "services.exe",
        "csrss.exe",
        "wininit.exe",
    ];

    for process_name in &system_process_names {
        for (_pid, process) in processes.iter() {
            if process.name.to_lowercase() == process_name.to_lowercase() {
                // 检查进程所有者是否为 SYSTEM
                if process.owner.to_lowercase().contains("system")
                    || process.owner.to_lowercase().contains("nt authority")
                {
                    if let Ok(token) = duplicate_system_token(process.pid) {
                        return Ok(token);
                    }
                }
            }
        }
    }

    Err(Error::from(HRESULT(0x80070005u32 as i32))) // ACCESS_DENIED
}

fn duplicate_system_token(pid: u32) -> Result<HANDLE> {
    unsafe {
        // 尝试以更高权限打开目标进程
        let process_handle =
            match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, pid) {
                Ok(handle) => handle,
                Err(_) => {
                    // 如果失败，尝试只使用 QUERY_INFORMATION
                    OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)?
                }
            };

        // 获取进程 token
        let mut token_handle: HANDLE = HANDLE::default();
        if let Err(e) = OpenProcessToken(
            process_handle,
            TOKEN_DUPLICATE | TOKEN_QUERY,
            &mut token_handle,
        ) {
            let _ = CloseHandle(process_handle);
            return Err(e);
        }

        // 复制 token
        let mut new_token_handle: HANDLE = HANDLE::default();
        if let Err(e) = DuplicateTokenEx(
            token_handle,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TOKEN_PRIMARY,
            &mut new_token_handle,
        ) {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(process_handle);
            return Err(e);
        }

        // 模拟用户
        if let Err(e) = ImpersonateLoggedOnUser(new_token_handle) {
            let _ = CloseHandle(new_token_handle);
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(process_handle);
            return Err(e);
        }

        // 清理资源
        let _ = CloseHandle(token_handle);
        let _ = CloseHandle(process_handle);

        Ok(new_token_handle)
    }
}

pub fn has_privilege(privilege_name: &str) -> Result<bool> {
    let token_handle = get_token(
        unsafe { GetCurrentProcessId() },
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
    )?;

    unsafe {
        let privilege_name = to_wide_string(privilege_name);
        let mut luid: LUID = LUID::default();

        LookupPrivilegeValueW(None, PWSTR(privilege_name.as_ptr() as *mut u16), &mut luid)?;

        let mut size: u32 = 0;
        let mut tp: TOKEN_PRIVILEGES = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        // 先尝试调整权限
        AdjustTokenPrivileges(
            token_handle,
            false,
            Some(&mut tp),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            Some(&mut size),
        )?;

        // 获取当前权限状态
        let mut buffer = vec![0u8; size as usize];
        let p_buffer = buffer.as_mut_ptr() as *mut TOKEN_PRIVILEGES;

        AdjustTokenPrivileges(
            token_handle,
            false,
            Some(&mut tp),
            size,
            Some(p_buffer),
            Some(&mut size),
        )?;

        let privileges = &*p_buffer;
        let _ = CloseHandle(token_handle);

        // 检查权限是否启用
        if privileges.PrivilegeCount > 0 {
            Ok((privileges.Privileges[0].Attributes & SE_PRIVILEGE_ENABLED)
                != TOKEN_PRIVILEGES_ATTRIBUTES(0))
        } else {
            Ok(false)
        }
    }
}
