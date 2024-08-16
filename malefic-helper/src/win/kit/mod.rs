use std::{ffi::{OsStr,OsString}, os::windows::prelude::{OsStrExt, OsStringExt}};
use winapi:: {
    um::{
        lmaccess::{
            NetLocalGroupEnum,
            NetLocalGroupGetMembers,
            LOCALGROUP_INFO_1,
            LOCALGROUP_MEMBERS_INFO_3
        },
        lmapibuf::NetApiBufferFree,
        winbase::{
            GetUserNameW, 
            LookupAccountNameW,
        },
        sysinfoapi::{
            ComputerNameDnsHostname,
            GetNativeSystemInfo, 
            GetComputerNameExW, 
            COMPUTER_NAME_FORMAT, 
            SYSTEM_INFO
        },
        winnt::{
            PSID,
            SID_NAME_USE,
            PSID_NAME_USE,
            SidTypeUnknown,
        },
        winnls::GetUserPreferredUILanguages,
        
    },
    shared::{
        sddl::ConvertSidToStringSidW,
        lmcons::MAX_PREFERRED_LENGTH
    }
};

pub static WIN11_BUILD_NUMBER :u32 = 22000;
pub static MUI_LANGUAGE_NAME: u32 = 0x8;

// pub fn rtl_get_version() -> Option<OSVERSIONINFOEXW> {
//     let mut os_version_info = std::mem::MaybeUninit::<RTL_OSVERSIONINFOEXW>::uninit();
//     unsafe {
//         ((*os_version_info.as_mut_ptr())).dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
//     }
//     // let status = unsafe { RtlGetVersion(&mut os_version_info) };
//     let status = unsafe { RtlGetVersion(os_version_info.as_mut_ptr() as *mut _) };
//     if status != 0 {
//         return None;
//     }
//     unsafe {
//         let os_version_info = os_version_info.assume_init();
//         return Some(os_version_info);
//     }
// }

pub fn get_computer_name_ex_w(kind: COMPUTER_NAME_FORMAT) -> Option<String> {
    let mut buffer_size = 0u32;

    unsafe {
        GetComputerNameExW(kind, 
                           std::ptr::null_mut(), 
                           &mut buffer_size);
    }

    // let mut buffer: Vec<u16> = Vec::with_capacity(buffer_size as usize);

    let mut buffer = vec![0u16; buffer_size as usize];
    let status = unsafe { 
        GetComputerNameExW(kind, 
                           buffer.as_mut_ptr(), 
                           &mut buffer_size) };
    if status == 0 {
        return None;
    }
    if let Some(pos) = buffer.iter().position(|c| *c == 0) {
        buffer.resize(pos, 0);
    }
    // Vec<u16> -> String
    return String::from_utf16(&buffer).ok();
}

pub fn get_native_system_info() -> Option<SYSTEM_INFO>{
    let mut system_info = std::mem::MaybeUninit::<SYSTEM_INFO>::uninit();
    unsafe {
        GetNativeSystemInfo(system_info.as_mut_ptr());
    }

    return Some(unsafe { system_info.assume_init().into() });
}

pub fn get_user_name_w() -> Option<String> {
    let mut buffer_size = 0u32;

    unsafe {
        GetUserNameW(std::ptr::null_mut(), 
                                  &mut buffer_size);
    }

    // let mut buffer: Vec<u16> = Vec::with_capacity(buffer_size as usize);
    let mut buffer = vec![0u16; (buffer_size) as usize];
    let status = unsafe { 
        GetUserNameW(buffer.as_mut_ptr(), &mut buffer_size) };
    if status == 0 {
        return None;
    }
    if let Some(pos) = buffer.iter().position(|c| *c == 0) {
        buffer.resize(pos, 0);
    }
    return String::from_utf16(&buffer).ok();
}
pub fn get_sid() -> Option<String> {
    let name = crate::win::kit::get_user_name_w();
    if name.is_none() {
        return None;
    }
    let name = name.unwrap();
    return crate::win::kit::look_up_account_name(name);
}

pub fn get_gid() -> Option<String> {
    let name = crate::win::kit::get_computer_name_ex_w(ComputerNameDnsHostname);
    if name.is_none() {
        return None;
    }
    let name = name.unwrap();
    return crate::win::kit::net_local_group_get_members(name);
}

pub fn get_user_preferred_ui_lang() -> Option<String> {
    let mut buffer_size = 0;
    let mut num_languages = 0;
    unsafe {
        GetUserPreferredUILanguages(MUI_LANGUAGE_NAME,
                                    &mut num_languages, 
                                    std::ptr::null_mut(), 
                                    &mut buffer_size);
    }
    let mut buffer = vec![0u16; buffer_size as usize];
    let status = unsafe { 
        GetUserPreferredUILanguages(MUI_LANGUAGE_NAME,
                                    &mut num_languages, 
                                    buffer.as_mut_ptr(), 
                                    &mut buffer_size) };
    if status == 0 {
        return None;
    }
    if let Some(pos) = buffer.iter().position(|c| *c == 0) {
        buffer.resize(pos, 0);
    }
    return String::from_utf16(&buffer).ok();
}

fn str2wsz(s: &str) -> Vec<u16> {
    return OsStr::new(s).encode_wide().chain(Some(0).into_iter()).collect::<Vec<u16>>();
}


pub fn get_string_from_pwstr(pwstr: *const u16) -> String {
    let len = (0..).take_while(|&i| unsafe { *pwstr.offset(i) != 0 }).count();
    let slice = unsafe { std::slice::from_raw_parts(pwstr, len) };
    let os_string = OsString::from_wide(slice);
    os_string.into_string().unwrap_or_else(|_| String::new())
}

pub fn convert_sid_to_string(sid: PSID) -> Option<String> {
    let mut sid_string = std::ptr::null_mut();
    let status = unsafe {
        ConvertSidToStringSidW(sid, 
                               &mut sid_string)
    };
    if status == 0 {
        if cfg!(debug_assertions) {
            println!("ConvertSidToStringSidW failed");
        }
        return None;
    }
    let sid_string = unsafe { sid_string.as_mut() };
    if sid_string.is_none() {
        if cfg!(debug_assertions) {
            println!("sid_string is None");
        }
        return None;
    }
    return Some(get_string_from_pwstr(sid_string.unwrap()));
}


pub fn look_up_account_name(username: String) -> Option<String> {
    let mut sid_buf_size = 0u32;
    let mut domain_name_buf_size = 0u32;
    let mut e_sid_type: SID_NAME_USE = SidTypeUnknown as SID_NAME_USE;
    let e_sid_type_p: PSID_NAME_USE = &mut e_sid_type as PSID_NAME_USE;
    let user = str2wsz(username.as_str());

    unsafe {
        LookupAccountNameW(std::ptr::null_mut(), 
                           user.as_ptr(), 
                           std::ptr::null_mut(), 
                           &mut sid_buf_size, 
                           std::ptr::null_mut(), 
                           &mut domain_name_buf_size, 
                           e_sid_type_p);
    }

    let mut sid_buf = vec![0u8; sid_buf_size as usize];
    let mut domain_name_buf = vec![0u16; domain_name_buf_size as usize];

    let status = unsafe {
        LookupAccountNameW(std::ptr::null_mut(), 
                           user.as_ptr(), 
                           sid_buf.as_mut_ptr() as PSID, 
                           &mut sid_buf_size, 
                           domain_name_buf.as_mut_ptr(), 
                           &mut domain_name_buf_size, 
                           e_sid_type_p)
    };

    if status == 0 {
        if cfg!(debug_assertions) {
            println!("LookupAccountNameW failed, lasterror is {:?}", unsafe { 
                winapi::um::errhandlingapi::GetLastError()
                 } );
        }
        return None;
    }

    return  convert_sid_to_string(sid_buf.as_mut_ptr() as PSID);

}


pub fn net_local_group_get_members(username: String) -> Option<String> {
    if cfg!(debug_assertions) {
        println!("username is {}", username);
    }
    let user = str2wsz(&username);
    let mut members_ptr: *mut LOCALGROUP_MEMBERS_INFO_3 = std::ptr::null_mut();
    let mut total_entries: u32 = 0;
    let mut entries_read: u32 = 0;
    let mut resume_handle: usize = 0;
    let result = unsafe {
        NetLocalGroupGetMembers(
            std::ptr::null_mut(),               // 本地计算机
            user.as_ptr(),      // 用户组名称
            3,                             // 信息级别
            &mut members_ptr as *mut _ as *mut *mut u8,  // 输出的成员信息指针
            MAX_PREFERRED_LENGTH,          // 最大首选长度
            &mut entries_read,             // 实际读取的条目数
            &mut total_entries,            // 总条目数
            &mut resume_handle,            // 恢复句柄
        )
    };
    if result != 0 {
        if cfg!(debug_assertions) {
            println!("NetLocalGroupGetMembers failed, lasterror is {:?}, result is {}", unsafe { 
                winapi::um::errhandlingapi::GetLastError()
                 }, result );
        }
        return None;
    }

    let mut current_member = members_ptr;
    let mut mem_str = String::new();
    for _ in 0..entries_read {
        let member_domaindname = unsafe {
            (*current_member).lgrmi3_domainandname
        };
        mem_str.push_str(&get_string_from_pwstr(member_domaindname));
        current_member = unsafe {
            current_member.offset(1)
        };
    }

    return Some(mem_str);
}

pub fn get_gid2() {
    let name = crate::win::kit::get_computer_name_ex_w(ComputerNameDnsHostname);
    if name.is_none() {
        return;
    }
    let name = name.unwrap();
    list_group_members(&name);
}

#[allow(dead_code)]
fn list_local_groups() {
    let mut group_info_ptr: *mut LOCALGROUP_INFO_1 = std::ptr::null_mut();
    let mut total_entries: u32 = 0;
    let mut entries_read: u32 = 0;
    let mut resume_handle: usize = 0;

    // 使用 NetLocalGroupEnum 函数获取本地计算机上的所有用户组
    let result = unsafe {
        NetLocalGroupEnum(
            std::ptr::null_mut(),               // 本地计算机
            1,                             // 信息级别
            &mut group_info_ptr as *mut _ as *mut *mut u8,  // 输出的用户组信息指针
            MAX_PREFERRED_LENGTH,          // 最大首选长度
            &mut entries_read,             // 实际读取的条目数
            &mut total_entries,            // 总条目数
            &mut resume_handle,            // 恢复句柄
        )
    };

    if result == 0 {
        println!("查询本地用户组失败.");
    } else {
        println!("本地用户组列表:");
        let mut current_group = group_info_ptr;
        for _ in 0..entries_read {
            let group_name = unsafe {(*current_group).lgrpi1_name};
            println!("  {}", get_string_from_pwstr(group_name));
            current_group = unsafe{current_group.offset(1)};
        }

        // 释放资源
        unsafe {
            NetApiBufferFree(group_info_ptr as *mut _);
        }
    }
}

fn list_group_members(group_name: &str) {
    // 将用户组名称转换为宽字符
    let group_name_wide: Vec<u16> = OsString::from(group_name)
        .encode_wide()
        .chain(Some(0).into_iter()) // 添加 NULL 终止符
        .collect();

    let mut members_ptr: *mut LOCALGROUP_MEMBERS_INFO_3 = std::ptr::null_mut();
    let mut total_entries: u32 = 0;
    let mut entries_read: u32 = 0;
    let mut resume_handle: usize = 0;

    // 使用 NetLocalGroupGetMembers 函数获取用户组成员信息
    let result = unsafe {
        NetLocalGroupGetMembers(
            std::ptr::null_mut(),               // 本地计算机
            group_name_wide.as_ptr(),      // 用户组名称
            3,                             // 信息级别
            &mut members_ptr as *mut _ as *mut *mut u8,  // 输出的成员信息指针
            MAX_PREFERRED_LENGTH,          // 最大首选长度
            &mut entries_read,             // 实际读取的条目数
            &mut total_entries,            // 总条目数
            &mut resume_handle,            // 恢复句柄
        )
    };

    if result == 0 {
        println!("查询用户组成员失败.");
    } else {
        println!("用户组 {} 的成员:", group_name);
        println!("entries is : {}", entries_read);
        let mut current_member = members_ptr;
        for _ in 0..entries_read {
            let member_sid = unsafe {(*current_member).lgrmi3_domainandname};
            // 注意：这里 member_sid 是一个包含域名和用户名的字符串
            println!("  {}", get_string_from_pwstr(member_sid));
            current_member = unsafe{current_member.offset(1)};
        }

        // 释放资源
        unsafe {
            NetApiBufferFree(members_ptr as _);
        }
    }
}