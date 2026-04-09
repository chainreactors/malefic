use core::ptr::null_mut;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::NetManagement::NetApiBufferFree;
use windows::Win32::Networking::ActiveDirectory::{
    DsGetDcNameW, DOMAIN_CONTROLLER_INFOW, DS_DIRECTORY_SERVICE_REQUIRED, DS_GC_SERVER_REQUIRED,
    DS_RETURN_DNS_NAME,
};

pub fn get_domain() -> String {
    let mut dc_info_ptr: *mut DOMAIN_CONTROLLER_INFOW = null_mut();
    let res = unsafe {
        DsGetDcNameW(
            None,
            None,
            None,
            None,
            DS_GC_SERVER_REQUIRED | DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME,
            &mut dc_info_ptr as *mut _,
        )
    };
    if res != ERROR_SUCCESS.0 || dc_info_ptr.is_null() {
        return "".to_string();
    }

    // Safety check: Ensure DomainName is not null
    if unsafe { (*dc_info_ptr).DomainName.0.is_null() } {
        unsafe {
            NetApiBufferFree(*dc_info_ptr.cast());
        }
        return "".to_string();
    }

    let domain_name = unsafe { pwstr_to_str((*dc_info_ptr).DomainName.0) };
    unsafe {
        NetApiBufferFree(*dc_info_ptr.cast());
    }
    return domain_name.to_string();
}

pub(crate) fn pwstr_to_str(ptr: *const u16) -> String {
    let mut len = 0;
    unsafe {
        while *(ptr.add(len)) != 0 {
            len += 1;
        }
    }
    let slice = unsafe { &*(std::ptr::slice_from_raw_parts(ptr, len)) };
    String::from_utf16_lossy(slice)
}
