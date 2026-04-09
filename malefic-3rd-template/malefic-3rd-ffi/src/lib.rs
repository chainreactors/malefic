//! Shared FFI utilities for malefic 3rd-party language modules.
//!
//! Provides:
//! - [`FfiBuffer`] — RAII guard for foreign-allocated memory
//! - [`ffi_free`] / [`ffi_module_name`] — C memory helpers
//! - [`encode_request`] / [`decode_response`] — protobuf serialization
//! - [`HandlerFn`] / [`ffi_handler_loop`] — bridge for synchronous handlers
//! - Re-exports of [`RtModule`], [`RtChannel`], [`RtResult`] for module implementations

pub use std::ffi::{c_char, c_int, c_uint, CStr};

// ── Runtime re-exports (used by all module wrappers) ────────────────────────

pub use malefic_runtime::module_sdk::{RtModule, RtChannel, RtResult, RtChannelError};
pub use malefic_proto::proto::implantpb::spite::Body;
pub use malefic_proto::proto::modulepb::{Request, Response};

// ── libc free ───────────────────────────────────────────────────────────────

extern "C" {
    fn free(ptr: *mut std::ffi::c_void);
}

/// Free a pointer allocated by foreign code (C `malloc` / Go `C.CBytes` / etc.).
///
/// # Safety
/// `ptr` must have been allocated by the C allocator (`malloc`).
pub unsafe fn ffi_free(ptr: *mut c_char) {
    free(ptr as *mut std::ffi::c_void);
}

// ── FfiBuffer ───────────────────────────────────────────────────────────────

/// RAII guard for a buffer allocated by foreign code via `malloc`.
/// On drop, calls `free()` to release the memory.
pub struct FfiBuffer {
    ptr: *mut c_char,
    len: usize,
}

impl FfiBuffer {
    /// # Safety
    /// `ptr` must be non-null, valid for `len` bytes, and allocated via `malloc`.
    pub unsafe fn new(ptr: *mut c_char, len: usize) -> Self {
        Self { ptr, len }
    }

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
/// `needs_free`: true for Go (heap-allocated `C.CString`), false for C/Zig/Nim (static).
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

pub fn encode_request(request: &Request) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    prost::Message::encode(request, &mut buf)
        .map_err(|e| format!("encode error: {}", e))?;
    Ok(buf)
}

pub fn decode_response(bytes: &[u8]) -> Result<Response, String> {
    prost::Message::decode(bytes)
        .map_err(|e| format!("decode error: {}", e))
}

// ── Synchronous FFI handler bridge ──────────────────────────────────────────

/// Signature shared by all synchronous FFI handlers (C / Zig / Nim).
pub type HandlerFn = unsafe extern "C" fn(
    c_uint, *const c_char, c_int, *mut *mut c_char, *mut c_int,
) -> c_int;

/// Bridge a synchronous `HandlerFn` into the `RtModule::run(channel)` protocol.
///
/// Buffers the previous result and sends it as an intermediate message when the
/// next request arrives. The final result is returned as `RtResult::Done`.
pub fn ffi_handler_loop(
    id: u32,
    channel: &RtChannel,
    handler: HandlerFn,
    handler_name: &str,
) -> RtResult {
    let mut last_response: Option<Body> = None;

    loop {
        let body = match channel.recv() {
            Ok(b) => b,
            Err(RtChannelError::Eof) => break,
            Err(e) => return RtResult::Error(format!("{}: recv: {}", handler_name, e)),
        };

        let request = match body {
            Body::Request(req) => req,
            _ => break,
        };

        if let Some(prev) = last_response.take() {
            if channel.send(prev).is_err() { break; }
        }

        let req_buf = match encode_request(&request) {
            Ok(b) => b,
            Err(e) => return RtResult::Error(format!("{}: {}", handler_name, e)),
        };

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
            return RtResult::Error(format!("{} failed (task {}, rc={})", handler_name, id, rc));
        }

        let response = if !resp_ptr.is_null() && resp_len > 0 {
            let buf = unsafe { FfiBuffer::new(resp_ptr, resp_len as usize) };
            match decode_response(buf.as_bytes()) {
                Ok(r) => r,
                Err(e) => return RtResult::Error(format!("{}: {}", handler_name, e)),
            }
        } else {
            if !resp_ptr.is_null() { unsafe { ffi_free(resp_ptr) }; }
            Response::default()
        };

        last_response = Some(Body::Response(response));
    }

    match last_response {
        Some(body) => RtResult::Done(body),
        None => RtResult::Error(format!("module {} produced no output", handler_name)),
    }
}
