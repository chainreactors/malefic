#![no_std]
#![no_main]
#![allow(non_snake_case)]

mod constants;
mod hash;
mod instance;
mod memory;
mod resolve;
mod windows;

pub use constants::*;
pub use hash::*;
pub use instance::*;
pub use resolve::*;
pub use windows::*;

// Stub for Windows GNU target: libcore.rlib contains .xdata unwind tables
// that reference rust_eh_personality even when panic=abort is set.
// Providing an empty stub satisfies the linker.
#[cfg(all(target_os = "windows", target_env = "gnu"))]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

use core::ffi::c_void;
use core::panic::PanicInfo;

// x64 entry point and RIP-relative helpers via global_asm
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".section .text$A,\"xr\"",
    ".global stardust",
    ".global RipStart",
    "stardust:",
    "push rsi",
    "mov rsi, rsp",
    "and rsp, -16",
    "sub rsp, 0x20",
    "call entry",
    "mov rsp, rsi",
    "pop rsi",
    "ret",
    "RipStart:",
    "call 2f",
    "ret",
    "2:",
    "mov rax, [rsp]",
    "sub rax, 0x1b",
    "ret",
);

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".section .text$C,\"xr\"",
    ".global RipData",
    "RipData:",
    "call 2f",
    "ret",
    "2:",
    "mov rax, [rsp]",
    "sub rax, 0x5",
    "ret",
);

// x86 entry point and RIP-relative helpers via global_asm
#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    ".section .text$A,\"xr\"",
    ".global _stardust",
    ".global _RipStart",
    "_stardust:",
    "push ebp",
    "mov ebp, esp",
    "call _entry",
    "mov esp, ebp",
    "pop ebp",
    "ret",
    "_RipStart:",
    "call 2f",
    "ret",
    "2:",
    "mov eax, [esp]",
    "sub eax, 0x11",
    "ret",
);

#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    ".section .text$C,\"xr\"",
    ".global _RipData",
    "_RipData:",
    "call 2f",
    "ret",
    "2:",
    "mov eax, [esp]",
    "sub eax, 0x5",
    "ret",
);

extern "C" {
    pub fn RipStart() -> usize;
    pub fn RipData() -> usize;
}

#[no_mangle]
pub unsafe extern "C" fn entry(args: *mut c_void) {
    let instance = instance::Instance::new();
    instance.start(args);
}

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _hinst: *mut c_void,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    if reason == 1 {
        // DLL_PROCESS_ATTACH
        entry(core::ptr::null_mut());
    }
    1
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub unsafe extern "C" fn __aeabi_unwind_cpp_pr0() {
    loop {}
}

#[export_name = "_fltused"]
static _FLTUSED: i32 = 0;
