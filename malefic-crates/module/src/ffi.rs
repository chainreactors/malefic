//! Shared FFI utilities for malefic 3rd-party language modules.
//!
//! Gated behind the `ffi` feature of `malefic-module`.
//!
//! Provides:
//! - [`FfiBuffer`] — RAII guard for foreign-allocated memory
//! - [`ffi_free`] / [`ffi_module_name`] — C memory helpers
//! - [`encode_request`] / [`decode_response`] — protobuf serialization
//! - [`HandlerFn`] / [`ffi_run_loop`] — streaming bridge for synchronous handlers

use std::ffi::{c_char, c_int, c_uint, CStr};

use crate::{Body, Input, ModuleResult, Output, TaskResult};
use malefic_proto::proto::modulepb::{Request, Response};

// Re-export FFI-relevant types for convenience (`use malefic_module::ffi::*`)
pub use anyhow::anyhow;
pub use async_trait::async_trait;

// ── libc free ───────────────────────────────────────────────────────────────

extern "C" {
    fn free(ptr: *mut std::ffi::c_void);
}

/// Free a pointer allocated by foreign code (C `malloc` / Go `C.CBytes` / etc.).
///
/// # Safety
/// `ptr` must have been allocated by the C allocator (`malloc`).
pub(crate) unsafe fn ffi_free(ptr: *mut c_char) {
    free(ptr as *mut std::ffi::c_void);
}

// ── FfiBuffer ───────────────────────────────────────────────────────────────

/// RAII guard for a buffer allocated by foreign code via `malloc`.
///
/// On drop, calls `free()` to release the memory.
/// This prevents leaks when decoding fails or an early return occurs.
pub struct FfiBuffer {
    ptr: *mut c_char,
    len: usize,
}

impl FfiBuffer {
    /// Wrap a foreign-allocated pointer.
    ///
    /// # Safety
    /// `ptr` must be non-null, valid for `len` bytes, and allocated via `malloc`.
    pub unsafe fn new(ptr: *mut c_char, len: usize) -> Self {
        Self { ptr, len }
    }

    /// View the buffer contents as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

impl Drop for FfiBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { ffi_free(self.ptr) };
        }
    }
}

// ── Module name retrieval ───────────────────────────────────────────────────

/// Retrieve a module name string from an FFI `name_fn`.
///
/// If `needs_free` is true, the returned C string pointer will be freed after
/// copying (Go-style, where the name is heap-allocated via `C.CString`).
/// If false, the pointer is assumed to be static (C/Zig/Nim-style).
///
/// # Safety
/// `name_fn` must return a valid, NUL-terminated C string.
pub unsafe fn ffi_module_name(
    name_fn: unsafe extern "C" fn() -> *const c_char,
    needs_free: bool,
) -> String {
    let ptr = name_fn();
    let name = CStr::from_ptr(ptr).to_string_lossy().into_owned();
    if needs_free {
        ffi_free(ptr as *mut c_char);
    }
    name
}

// ── Protobuf encode / decode ────────────────────────────────────────────────

/// Encode a prost `Request` into bytes suitable for passing across FFI.
pub fn encode_request(request: &Request) -> anyhow::Result<Vec<u8>> {
    use prost::Message;
    let mut buf = Vec::new();
    request
        .encode(&mut buf)
        .map_err(|e| anyhow::anyhow!("encode error: {}", e))?;
    Ok(buf)
}

/// Decode a prost `Response` from bytes returned by foreign code.
pub fn decode_response(bytes: &[u8]) -> anyhow::Result<Response> {
    use prost::Message;
    Response::decode(bytes).map_err(|e| anyhow::anyhow!("decode error: {}", e))
}

// ── Streaming FFI bridge ────────────────────────────────────────────────────

/// Signature shared by all synchronous FFI handlers (C / Zig / Nim).
pub type HandlerFn =
    unsafe extern "C" fn(c_uint, *const c_char, c_int, *mut *mut c_char, *mut c_int) -> c_int;

/// Consume every `Request` from `receiver`, call `handler` for each one,
/// forward intermediate results through `sender`, and return the last result.
///
/// This gives synchronous FFI handlers (C/Zig/Nim) multi-round streaming
/// capability without any changes to the foreign-language source code.
pub async fn ffi_run_loop(
    id: u32,
    receiver: &mut Input,
    sender: &mut Output,
    handler: HandlerFn,
    handler_name: &str,
) -> ModuleResult {
    use futures::StreamExt;

    let mut last_result: Option<TaskResult> = None;

    while let Some(body) = receiver.next().await {
        if let Body::Request(request) = body {
            let req_buf = encode_request(&request)?;

            let mut resp_ptr: *mut c_char = std::ptr::null_mut();
            let mut resp_len: c_int = 0;

            let rc = unsafe {
                handler(
                    id as c_uint,
                    req_buf.as_ptr() as *const c_char,
                    req_buf.len() as c_int,
                    &mut resp_ptr,
                    &mut resp_len,
                )
            };

            if rc != 0 {
                return Err(
                    anyhow::anyhow!("{} failed (task {}, rc={})", handler_name, id, rc).into(),
                );
            }

            let response = if !resp_ptr.is_null() && resp_len > 0 {
                let buf = unsafe { FfiBuffer::new(resp_ptr, resp_len as usize) };
                decode_response(buf.as_bytes())?
            } else {
                if !resp_ptr.is_null() {
                    unsafe { ffi_free(resp_ptr) };
                }
                Response::default()
            };

            let task_result = TaskResult::new_with_body(id, Body::Response(response));

            // Forward the previous result as an intermediate message.
            if let Some(prev) = last_result.take() {
                let _ = sender.unbounded_send(prev);
            }
            last_result = Some(task_result);
        } else {
            break;
        }
    }

    last_result.ok_or_else(|| anyhow::anyhow!("module {} produced no output", handler_name).into())
}
