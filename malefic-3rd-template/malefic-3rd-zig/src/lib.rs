use malefic_3rd_ffi::*;
use std::ffi::{c_char, c_int, c_uint};

extern "C" {
    fn ZigModuleName() -> *const c_char;
    fn ZigModuleHandle(
        task_id: c_uint,
        req_data: *const c_char,
        req_len: c_int,
        resp_data: *mut *mut c_char,
        resp_len: *mut c_int,
    ) -> c_int;
}

pub struct ZigModule {
    name: String,
}

impl RtModule for ZigModule {
    fn name() -> &'static str { "example_zig" }

    fn new() -> Self {
        let name = unsafe { ffi_module_name(ZigModuleName, false) };
        Self { name }
    }

    fn run(&mut self, id: u32, ch: &RtChannel) -> RtResult {
        ffi_handler_loop(id, ch, ZigModuleHandle, "ZigModuleHandle")
    }
}
