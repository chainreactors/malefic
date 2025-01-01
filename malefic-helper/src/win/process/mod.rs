use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
use windows::Win32::System::Threading::{ IsWow64Process, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::Security::{GetTokenInformation, LookupAccountSidW, TokenUser, SID_NAME_USE, TOKEN_QUERY};
use std::ffi::{c_void, OsString};
use windows::core::{Result, PWSTR};
use windows::Win32::System::SystemInformation::{GetNativeSystemInfo, PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_INTEL, SYSTEM_INFO};
use std::os::windows::ffi::OsStringExt;
use crate::win::common::get_buffer;

pub fn get_process_architecture(pid: u32) -> Result<String> {
    unsafe {
        let process_handle: HANDLE = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?;

        let mut system_info: SYSTEM_INFO = std::mem::zeroed();
        GetNativeSystemInfo(&mut system_info);

        let mut is_wow64: BOOL = BOOL(0);


        IsWow64Process(process_handle, &mut is_wow64)?;

        if is_wow64.as_bool() {
            Ok("x86".to_string())
        } else {
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
}

pub fn get_process_owner(pid: u32) -> anyhow::Result<String> {
    unsafe {
        // 打开进程，获取查询权限
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?;
        if process_handle.is_invalid() {
            return Err(anyhow::anyhow!("OpenProcess failed"));
        }

        // 打开进程 token
        let mut token_handle: HANDLE = HANDLE::default();
        if !OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle).is_ok() {
            let _ = CloseHandle(process_handle);
            return Err(anyhow::anyhow!("OpenProcessToken failed"));
        }


        let mut token_info_len: u32 = 0;
        let success = GetTokenInformation(token_handle, TokenUser, None, 0, &mut token_info_len);
        
        get_buffer(success).map_err(|e| {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(process_handle);
            e
        })?;
        

        // 分配缓冲区存储 token 信息
        let mut token_info = vec![0u8; token_info_len as usize];
        let result = GetTokenInformation(
            token_handle,
            TokenUser,
            Some(token_info.as_mut_ptr() as *mut c_void),
            token_info_len,
            &mut token_info_len,
        );

        // 检查第二次调用 GetTokenInformation 的结果
        if result.is_err() {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(process_handle);
            return Err(result.err().unwrap().into());
        }

        let token_user = &*(token_info.as_ptr() as *const windows::Win32::Security::SID_AND_ATTRIBUTES);

        // 预分配较大的缓冲区以避免重新分配
        let mut name = vec![0u16; 512];
        let mut domain_name = vec![0u16; 512];
        let mut name_len = name.len() as u32;
        let mut domain_name_len = domain_name.len() as u32;
        let mut sid_type = SID_NAME_USE::default();

        // 使用 PWSTR 包装指针
        let lookup_result = LookupAccountSidW(
            None,
            token_user.Sid,
            PWSTR(name.as_mut_ptr()),
            &mut name_len,
            PWSTR(domain_name.as_mut_ptr()),
            &mut domain_name_len,
            &mut sid_type,
        );

        // 检查 LookupAccountSidW 的结果
        if lookup_result.is_err() {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(process_handle);
            return Err(lookup_result.err().unwrap().into());
        }

        // 关闭句柄
        let _ = CloseHandle(token_handle);
        let _ = CloseHandle(process_handle);

        Ok(format!(
            "{}\\{}",
            OsString::from_wide(&domain_name[..domain_name_len as usize])
                .to_string_lossy()
                .into_owned(),
            OsString::from_wide(&name[..name_len as usize])
                .to_string_lossy()
                .into_owned()
        ))
    }
}