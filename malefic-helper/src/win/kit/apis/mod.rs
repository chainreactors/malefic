pub fn m_load_library_a(
    lib_filename: *const u8
) -> *const core::ffi::c_void {
    #[cfg(feature = "prebuild")]
    {
        use crate::win::kit::MLoadLibraryA;
        unsafe {
            MLoadLibraryA(lib_filename as _)
        }
    }
    #[cfg(feature = "source")]
    {
        unsafe {
            use malefic_win_kit::apis::Core::Foundation::MLoadLibraryA;
            MLoadLibraryA(lib_filename as _)
        }
    }
}

pub fn m_get_proc_address(
    module: *const core::ffi::c_void, 
    proc_name: *const u8
) -> *const core::ffi::c_void {
    #[cfg(feature = "prebuild")]
    {
        use crate::win::kit::MGetProcAddress;
        unsafe {
            MGetProcAddress(module as _, proc_name as _)
        }
    }
    #[cfg(feature = "source")]
    {
        unsafe {
            use malefic_win_kit::apis::Core::Foundation::MGetProcAddress;
            MGetProcAddress(module as _, proc_name as _)
        }
    }
}