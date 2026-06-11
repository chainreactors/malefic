use malefic_3rd_ffi::*;
use std::ffi::{c_char, c_int, c_uint};

extern "C" {
    fn NimMain();
    fn NimModuleName() -> *const c_char;
    fn NimModuleHandle(
        task_id: c_uint,
        req_data: *const c_char,
        req_len: c_int,
        resp_data: *mut *mut c_char,
        resp_len: *mut c_int,
    ) -> c_int;
}

static NIM_INIT: std::sync::Once = std::sync::Once::new();

pub struct NimModule {
    name: String,
}

impl RtModule for NimModule {
    fn name() -> &'static str { "example_nim" }

    fn new() -> Self {
        NIM_INIT.call_once(|| unsafe { NimMain() });
        let name = unsafe { ffi_module_name(NimModuleName, false) };
        Self { name }
    }

    fn run(&mut self, id: u32, ch: &RtChannel) -> RtResult {
        ffi_handler_loop(id, ch, NimModuleHandle, "NimModuleHandle")
    }
}
