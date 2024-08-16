pub type LoadLibraryA = unsafe extern "system" fn(
    lplibfilename: *const u8
) -> *mut ::core::ffi::c_void;

pub type GetProcAddress = unsafe extern "system" fn(
    hmodule: *mut ::core::ffi::c_void,
    lpprocname: *const u8
) -> *mut ::core::ffi::c_void;