use malefic_3rd_ffi::*;
use std::ffi::{c_char, c_int, c_uint};

extern "C" {
    fn CModuleName() -> *const c_char;
    fn CModuleHandle(
        task_id: c_uint,
        req_data: *const c_char,
        req_len: c_int,
        resp_data: *mut *mut c_char,
        resp_len: *mut c_int,
    ) -> c_int;
}

pub struct CModule {
    name: String,
}

impl RtModule for CModule {
    fn name() -> &'static str { "example_c" }

    fn new() -> Self {
        let name = unsafe { ffi_module_name(CModuleName, false) };
        Self { name }
    }

    fn run(&mut self, id: u32, ch: &RtChannel) -> RtResult {
        ffi_handler_loop(id, ch, CModuleHandle, "CModuleHandle")
    }
}
