pub unsafe fn get_func_addr(module: *const core::ffi::c_void, func_name: String) -> *const core::ffi::c_void {
    #[cfg(feature = "prebuild")]
    {
        use super::bindings::MaleficGetFuncAddrWithModuleBaseDefault;
        MaleficGetFuncAddrWithModuleBaseDefault(module, func_name.as_ptr() as _, func_name.len())
    }
    #[cfg(feature = "source")]
    {
        use malefic_win_kit::dynamic::DynamicLibraryUtils::GetFuncAddrWithModuleBaseDefault;
        GetFuncAddrWithModuleBaseDefault(module, &func_name.as_bytes())
    }
}