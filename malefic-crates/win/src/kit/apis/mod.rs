use crate::kit::binding::{
    MCreateThread, MGetCurrentProcess, MGetProcAddress, MLoadLibraryA, MNtCreateThreadEx,
    MaleficGetFuncAddrWithModuleBaseDefault,
};

pub unsafe fn m_load_library_a(lib_filename: *const u8) -> *const core::ffi::c_void {
    MLoadLibraryA(lib_filename) as _
}

pub unsafe fn m_get_proc_address(
    module: *const core::ffi::c_void,
    proc_name: *const u8,
) -> *const core::ffi::c_void {
    MGetProcAddress(module, proc_name)
}

pub unsafe fn m_create_thread(
    thread_attributes: *mut core::ffi::c_void,
    stack_size: u32,
    start_address: *mut core::ffi::c_void,
    parameter: *mut core::ffi::c_void,
    creation_flags: u32,
    thread_id: *mut u32,
) -> *mut core::ffi::c_void {
    MCreateThread(
        thread_attributes,
        stack_size,
        start_address,
        parameter,
        creation_flags,
        thread_id,
    )
}

pub unsafe fn m_nt_create_thread_ex(
    thread_handle: *mut core::ffi::c_void,
    desired_access: u32,
    object_attributes: *mut core::ffi::c_void,
    process_handle: *mut core::ffi::c_void,
    start_address: *mut core::ffi::c_void,
    start_parameter: *mut core::ffi::c_void,
    create_suspended: i32,
    stack_zero_bits: u32,
    size_of_stack_commit: u32,
    size_of_stack_reserve: u32,
    attribute_list: *mut core::ffi::c_void,
) -> i32 {
    MNtCreateThreadEx(
        thread_handle,
        desired_access,
        object_attributes,
        process_handle,
        start_address,
        start_parameter,
        create_suspended,
        stack_zero_bits,
        size_of_stack_commit,
        size_of_stack_reserve,
        attribute_list,
    )
}

pub unsafe fn m_get_current_process() -> *mut core::ffi::c_void {
    MGetCurrentProcess()
}

pub unsafe fn m_get_func_addr_with_module_base(
    module_base: *const core::ffi::c_void,
    func_name: &[u8],
) -> *const core::ffi::c_void {
    MaleficGetFuncAddrWithModuleBaseDefault(module_base, func_name.as_ptr(), func_name.len())
}
