pub type VirtualAlloc = unsafe extern "system" fn(
    lpaddress: *const ::core::ffi::c_void,
    dwsize: usize,
    flallocationtype: u32,
    flprotect: u32 
) -> *mut ::core::ffi::c_void;