//! C ABI type definitions for the malefic module runtime protocol.
//!
//! All types here are `#[repr(C)]` and use only C-compatible primitives.
//! This ensures binary compatibility across Rust versions, targets, and toolchains.

use core::ffi::c_void;

/// ABI version. Host checks this before calling any other export.
/// Bump when the protocol changes in an incompatible way.
pub const RT_ABI_VERSION: u32 = 2;

// ── Buffer ──────────────────────────────────────────────────────────────────

/// A buffer allocated by one side of the FFI boundary.
///
/// The allocating side provides a free function (`rt_free` for module-allocated,
/// `RtHostFreeFn` for host-allocated). The other side must NOT free it directly.
#[repr(C)]
#[derive(Debug)]
pub struct RtBuffer {
    pub ptr: *mut u8,
    pub len: u32,
}

impl RtBuffer {
    pub const fn empty() -> Self {
        Self {
            ptr: core::ptr::null_mut(),
            len: 0,
        }
    }

    pub fn from_vec(v: Vec<u8>) -> Self {
        let mut v = v.into_boxed_slice();
        let ptr = v.as_mut_ptr();
        let len = v.len() as u32;
        core::mem::forget(v);
        Self { ptr, len }
    }

    pub unsafe fn as_bytes(&self) -> &[u8] {
        if self.ptr.is_null() || self.len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(self.ptr, self.len as usize)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ptr.is_null() || self.len == 0
    }
}

/// Free a buffer created via [`RtBuffer::from_vec`].
///
/// # Safety
/// Must only be called on buffers created from `Vec<u8>` in the same binary.
pub unsafe fn rt_buffer_from_vec_free(buf: RtBuffer) {
    if !buf.ptr.is_null() && buf.len > 0 {
        let _ = Vec::from_raw_parts(buf.ptr, buf.len as usize, buf.len as usize);
    }
}

// ── Status ──────────────────────────────────────────────────────────────────

/// Status code returned by `rt_module_run`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtStatus {
    /// Error occurred. `final_out` contains UTF-8 error message.
    Error = 1,
    /// Module run completed successfully. `final_out` contains encoded Spite.
    Done = 2,
}

// ── Module Handle ───────────────────────────────────────────────────────────

/// Opaque handle to a module instance on the DLL side.
///
/// Created by `rt_module_create`, destroyed by `rt_module_destroy`.
/// The host must not inspect or dereference this pointer.
#[repr(C)]
pub struct RtModuleHandle {
    _opaque: [u8; 0],
}

// ── Callback Types ──────────────────────────────────────────────────────────

/// Module → Host: push output data.
///
/// The host copies `data[0..len]` before returning. The module may free
/// or reuse its buffer after this call returns.
///
/// Returns: `0` = ok, `-1` = host channel closed (module should exit).
pub type RtSendFn = unsafe extern "C" fn(ctx: *mut c_void, data: *const u8, len: u32) -> i32;

/// Host → Module: pull input data (blocking).
///
/// Blocks until the host has data available. On success, `*out_data` and
/// `*out_len` are set to a host-allocated buffer. The module must call
/// `RtHostFreeFn` to release it after reading.
///
/// Returns: `0` = ok, `-1` = EOF (no more input, module should exit).
pub type RtRecvFn =
    unsafe extern "C" fn(ctx: *mut c_void, out_data: *mut *mut u8, out_len: *mut u32) -> i32;

/// Host → Module: non-blocking receive.
///
/// Same as `RtRecvFn` but returns immediately if no data is available.
///
/// Returns: `0` = data available, `-1` = no data (would block), `-2` = EOF.
pub type RtTryRecvFn =
    unsafe extern "C" fn(ctx: *mut c_void, out_data: *mut *mut u8, out_len: *mut u32) -> i32;

/// Free a buffer allocated by the host (returned by `RtRecvFn` / `RtTryRecvFn`).
pub type RtHostFreeFn = unsafe extern "C" fn(ptr: *mut u8, len: u32);
