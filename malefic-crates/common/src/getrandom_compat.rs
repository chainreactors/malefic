//! Linker shim: strong `getrandom()` symbol for glibc < 2.25 cross-compilation.
//!
//! Rust std uses `#[linkage = "extern_weak"]` to reference `getrandom()`,
//! but zig's linker (targeting old glibc) cannot resolve the weak symbol.
//! This strong definition overrides the weak reference. It forwards directly
//! to `syscall(SYS_getrandom, ...)` which works on kernels >= 3.17.

#[no_mangle]
pub unsafe extern "C" fn getrandom(
    buf: *mut core::ffi::c_void,
    buflen: usize,
    flags: core::ffi::c_uint,
) -> isize {
    // libc::syscall() already handles errno (returns -1 and sets errno on error),
    // so we just forward the return value directly.
    libc::syscall(libc::SYS_getrandom, buf, buflen, flags) as isize
}
