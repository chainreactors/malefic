pub mod inlinepe;
pub mod reflective_loader;
pub mod runpe;
pub mod utils;

use crate::kit::binding::{HijackCommandLine, PELoader, RunSacrifice, UnloadPE};

pub unsafe fn unload_pe(pe_loader: *mut core::ffi::c_void) {
    UnloadPE(pe_loader as _);
}

pub unsafe fn unload_pe_no_tls(pe_loader: *mut core::ffi::c_void) {
    UnloadPE(pe_loader as _);
}

pub unsafe fn hijack_commandline(commandline: &Option<String>) -> bool {
    let s = String::new();
    let commandline = match commandline.as_ref() {
        Some(c) => c,
        None => &s,
    };
    HijackCommandLine(commandline.as_ptr(), commandline.len()) != 0
}

pub unsafe fn load_pe(
    bin: Vec<u8>,
    magic: Option<u16>,
    signature: Option<u32>,
) -> *const core::ffi::c_void {
    if bin.is_empty() {
        return std::ptr::null();
    }
    PELoader(
        std::ptr::null(),
        bin.as_ptr() as _,
        bin.len(),
        magic.is_some(),
        signature.is_some(),
        magic.unwrap_or(0),
        signature.unwrap_or(0),
    )
}

pub unsafe fn run_sacrifice(
    application_name: *mut u8,
    start_commandline: &[u8],
    hijack_commandline: &[u8],
    parent_id: u32,
    need_output: bool,
    block_dll: bool,
) -> Vec<u8> {
    RunSacrifice(
        application_name,
        start_commandline.as_ptr(),
        start_commandline.len(),
        hijack_commandline.as_ptr(),
        hijack_commandline.len(),
        parent_id,
        need_output,
        block_dll,
    )
    .into_bytes()
}
