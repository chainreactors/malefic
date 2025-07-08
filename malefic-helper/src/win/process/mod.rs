use crate::common::process::Process;
use crate::debug;
use std::collections::HashMap;
use std::ffi::OsString;
use std::mem::MaybeUninit;
use std::os::windows::ffi::OsStringExt;
use std::ptr::null_mut;
use windows::core::{PCWSTR, PWSTR};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, BOOL, HANDLE, HLOCAL, MAX_PATH, UNICODE_STRING,
};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, TokenUser, SID_NAME_USE, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows::Win32::System::SystemInformation::{
    GetNativeSystemInfo, PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_INTEL, SYSTEM_INFO,
};
use windows::Win32::System::Threading::{
    IsWow64Process, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use windows::Win32::UI::Shell::CommandLineToArgvW;

pub fn get_processes() -> anyhow::Result<HashMap<u32, Process>> {
    let mut processes = HashMap::new();
    unsafe {
        let h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;

        let mut pe32 = PROCESSENTRY32W::default();
        pe32.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(h_snapshot, &mut pe32).is_ok() {
            loop {
                let pid = pe32.th32ProcessID;
                let ppid = pe32.th32ParentProcessID;

                let name = String::from_utf16_lossy(
                    &pe32.szExeFile[..pe32
                        .szExeFile
                        .iter()
                        .position(|&x| x == 0)
                        .unwrap_or(pe32.szExeFile.len())],
                );

                let (path, arch, owner, args) = if let Some(handle) = get_process_handle(pid) {
                    (
                        get_process_path(handle),
                        get_process_architecture(handle).unwrap_or_default(),
                        get_process_owner(handle).unwrap_or_default(),
                        get_process_args(handle),
                    )
                } else {
                    (String::new(), String::new(), String::new(), String::new())
                };

                processes.insert(
                    pid,
                    Process {
                        name,
                        pid,
                        ppid,
                        arch,
                        owner,
                        path,
                        args,
                    },
                );

                if Process32NextW(h_snapshot, &mut pe32).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(h_snapshot);
    }

    Ok(processes)
}

pub fn get_process_handle(pid: u32) -> Option<HANDLE> {
    if pid == 0 {
        return None;
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;
        Some(handle)
    }
}

pub fn get_process_path(handle: HANDLE) -> String {
    unsafe {
        let mut path_buf = [0u16; MAX_PATH as usize + 1];
        let len = GetModuleFileNameExW(handle, None, &mut path_buf);
        if len > 0 {
            String::from_utf16_lossy(&path_buf[..len as usize])
        } else {
            String::new()
        }
    }
}

pub fn get_process_architecture(handle: HANDLE) -> anyhow::Result<String> {
    unsafe {
        let mut system_info: SYSTEM_INFO = std::mem::zeroed();
        GetNativeSystemInfo(&mut system_info);

        let mut is_wow64: BOOL = BOOL(0);

        if IsWow64Process(handle, &mut is_wow64).is_ok() {
            if is_wow64.as_bool() {
                return Ok("x86".to_string());
            }
        }

        let arch = system_info.Anonymous.Anonymous.wProcessorArchitecture;
        if arch == PROCESSOR_ARCHITECTURE_AMD64 {
            Ok("x64".to_string())
        } else if arch == PROCESSOR_ARCHITECTURE_INTEL {
            Ok("x86".to_string())
        } else {

            Ok("Unknown".to_string())
        }
    }
}

pub fn get_process_owner(handle: HANDLE) -> anyhow::Result<String> {
    unsafe {
        let mut token_handle = HANDLE::default();
        if !OpenProcessToken(handle, TOKEN_QUERY, &mut token_handle).is_ok() {
            return Err(anyhow::anyhow!("Failed to open process token"));
        }

        let mut token_info_len = 0u32;
        #[allow(unused_must_use)]
        {
            GetTokenInformation(token_handle, TokenUser, None, 0, &mut token_info_len);
        }

        let mut token_info = vec![0u8; token_info_len as usize];
        GetTokenInformation(
            token_handle,
            TokenUser,
            Some(token_info.as_mut_ptr() as *mut _),
            token_info_len,
            &mut token_info_len,
        )?;

        let token_user = &*(token_info.as_ptr() as *const windows::Win32::Security::TOKEN_USER);

        let mut name_buf = vec![0u16; 256];
        let mut domain_buf = vec![0u16; 256];
        let mut name_len = name_buf.len() as u32;
        let mut domain_len = domain_buf.len() as u32;
        let mut sid_type = SID_NAME_USE::default();

        let name = PWSTR(name_buf.as_mut_ptr());
        let domain = PWSTR(domain_buf.as_mut_ptr());

        LookupAccountSidW(
            PCWSTR::null(),
            token_user.User.Sid,
            name,
            &mut name_len,
            domain,
            &mut domain_len,
            &mut sid_type,
        )?;

        let _ = CloseHandle(token_handle);

        let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);
        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);

        Ok(format!("{}\\{}", domain, name))
    }
}

pub fn get_current_pid() -> u32 {
    std::process::id()
}

pub fn get_parent_pid() -> anyhow::Result<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        let mut process_entry = PROCESSENTRY32W::default();
        process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut process_entry).is_ok() {
            let current_process_id = get_current_pid();

            loop {
                if process_entry.th32ProcessID == current_process_id {
                    let _ = CloseHandle(snapshot);
                    return Ok(process_entry.th32ParentProcessID);
                }

                if !Process32NextW(snapshot, &mut process_entry).is_ok() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        Err(anyhow::anyhow!("Parent process not found"))
    }
}

pub fn get_current_process_name() -> String {
    if let Ok(path) = std::env::current_exe() {
        path.file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default()
            .to_string()
    } else {
        String::new()
    }
}

unsafe fn ph_query_process_variable_size(
    process_handle: HANDLE,
    process_information_class: PROCESSINFOCLASS,
) -> Option<Vec<u16>> {
    let mut return_length = 0u32;
    
    let _ = NtQueryInformationProcess(
        process_handle,
        process_information_class,
        null_mut(),
        0,
        &mut return_length,
    );
    
    // 分配足够的空间来存储UNICODE_STRING结构
    let mut buffer = vec![0u8; return_length as usize];
    if NtQueryInformationProcess(
        process_handle,
        process_information_class,
        buffer.as_mut_ptr() as *mut _,
        return_length,
        &mut return_length,
    )
    .is_err()
    {
        debug!("Failed to read process information");
        return None;
    }

    // 解析UNICODE_STRING结构
    let unicode_str = &*(buffer.as_ptr() as *const UNICODE_STRING);
    
    // 计算实际的字符数（Length是字节数，UTF-16每个字符2字节）
    let str_len = unicode_str.Length as usize / 2;
    let mut result = vec![0u16; str_len];

    // 从Buffer中复制实际的字符串内容
    if str_len > 0 {
        std::ptr::copy_nonoverlapping(unicode_str.Buffer.0, result.as_mut_ptr(), str_len);
    }
    
    Some(result)
}

unsafe fn get_cmdline_from_buffer(buffer: PCWSTR) -> Vec<OsString> {
    // Get argc and argv from the command line
    let mut argc = MaybeUninit::<i32>::uninit();
    let argv_p = CommandLineToArgvW(buffer, argc.as_mut_ptr());
    if argv_p.is_null() {
        return Vec::new();
    }
    let argc = argc.assume_init();
    let argv: &[PWSTR] = std::slice::from_raw_parts(argv_p, argc as usize);

    let mut res = Vec::new();
    for arg in argv {
        res.push(OsString::from_wide(arg.as_wide()));
    }

    let _err = LocalFree(HLOCAL(argv_p as _));

    res
}

fn get_process_args(handle: HANDLE) -> String {
    unsafe {
        if let Some(buffer) = ph_query_process_variable_size(handle, PROCESSINFOCLASS(60)) {
            if buffer.is_empty() {
                return String::new();
            }

            let buffer = PCWSTR::from_raw(buffer.as_ptr());
            let args = get_cmdline_from_buffer(buffer);
            if !args.is_empty() {
                args.iter()
                    .map(|s| s.to_string_lossy().into_owned())
                    .collect::<Vec<String>>()
                    .join(" ")
            } else {
                String::new()
            }
        } else {
            debug!("Failed to get process command line buffer");
            String::new()
        }
    }
}

pub fn get_process_info(pid: u32) -> anyhow::Result<Process> {
    unsafe {
        let handle =
            get_process_handle(pid).ok_or_else(|| anyhow::anyhow!("Failed to open process"))?;

        // 获取进程名称
        let mut pe32 = PROCESSENTRY32W::default();
        pe32.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ppid = 0;
        let mut name = String::new();

        let h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        if Process32FirstW(h_snapshot, &mut pe32).is_ok() {
            while Process32NextW(h_snapshot, &mut pe32).is_ok() {
                if pe32.th32ProcessID == pid {
                    ppid = pe32.th32ParentProcessID;
                    name = String::from_utf16_lossy(
                        &pe32.szExeFile[..pe32
                            .szExeFile
                            .iter()
                            .position(|&x| x == 0)
                            .unwrap_or(pe32.szExeFile.len())],
                    );
                    break;
                }
            }
        }
        let _ = CloseHandle(h_snapshot);

        // 获取其他信息
        let path = get_process_path(handle);
        let arch = get_process_architecture(handle).unwrap_or_default();
        let owner = get_process_owner(handle).unwrap_or_default();
        let args = get_process_args(handle);

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
