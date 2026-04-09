//! Module SDK for building cross-version module DLLs.
//!
//! Module authors implement [`RtModule`] for each module, then use
//! [`register_rt_modules!`] to generate the required C ABI exports.
//!
//! The module receives an [`RtChannel`] providing `send()`, `recv()`, and
//! `try_recv()` for full bidirectional streaming with the host.
//!
//! # Example
//!
//! ```rust,ignore
//! use malefic_runtime::module_sdk::*;
//! use malefic_proto::proto::implantpb::spite::Body;
//! use malefic_proto::proto::modulepb::Response;
//!
//! struct MyModule;
//!
//! impl RtModule for MyModule {
//!     fn name() -> &'static str { "my_module" }
//!     fn new() -> Self { Self }
//!     fn run(&mut self, task_id: u32, ch: &RtChannel) -> RtResult {
//!         let input = ch.recv()?;
//!         // process...
//!         ch.send(Body::Response(Response::default()))?;
//!         RtResult::Done(Body::Empty(Default::default()))
//!     }
//! }
//!
//! malefic_runtime::register_rt_modules!(MyModule);
//! ```

use crate::abi::{RtHostFreeFn, RtRecvFn, RtSendFn, RtTryRecvFn};
use core::ffi::c_void;
use malefic_proto::proto::implantpb::spite::Body;

// ── RtChannel ───────────────────────────────────────────────────────────────

/// Safe bidirectional channel for module ↔ host communication.
///
/// Wraps the C ABI callback pointers in a safe Rust API.
/// Provided to modules in [`RtModule::run()`].
pub struct RtChannel {
    task_id: u32,
    ctx: *mut c_void,
    send_fn: RtSendFn,
    recv_fn: RtRecvFn,
    try_recv_fn: RtTryRecvFn,
    host_free: RtHostFreeFn,
}

// Safety: RtChannel is used only within a single rt_module_run call on one thread.
unsafe impl Send for RtChannel {}

impl RtChannel {
    /// Construct from raw C pointers. Called by macro-generated code.
    ///
    /// # Safety
    /// All function pointers must be valid for the duration of the module's `run()`.
    #[doc(hidden)]
    pub unsafe fn from_raw(
        task_id: u32,
        ctx: *mut c_void,
        send_fn: RtSendFn,
        recv_fn: RtRecvFn,
        try_recv_fn: RtTryRecvFn,
        host_free: RtHostFreeFn,
    ) -> Self {
        Self {
            task_id,
            ctx,
            send_fn,
            recv_fn,
            try_recv_fn,
            host_free,
        }
    }

    /// Push a `Body` to the host (intermediate output).
    ///
    /// Returns `Err(Closed)` if the host has closed the output channel.
    pub fn send(&self, body: Body) -> Result<(), RtChannelError> {
        let bytes = crate::codec::encode_body(self.task_id, body);
        let rc = unsafe { (self.send_fn)(self.ctx, bytes.as_ptr(), bytes.len() as u32) };
        if rc == 0 {
            Ok(())
        } else {
            Err(RtChannelError::Closed)
        }
    }

    /// Pull a `Body` from the host (blocking).
    ///
    /// Blocks until the host sends data. Returns `Err(Eof)` when no more
    /// input will arrive (host closed the channel or task was cancelled).
    pub fn recv(&self) -> Result<Body, RtChannelError> {
        let mut ptr: *mut u8 = core::ptr::null_mut();
        let mut len: u32 = 0;
        let rc = unsafe { (self.recv_fn)(self.ctx, &mut ptr, &mut len) };
        if rc != 0 {
            return Err(RtChannelError::Eof);
        }
        let result = self.decode_and_free(ptr, len);
        result
    }

    /// Non-blocking receive.
    ///
    /// Returns `Ok(Some(body))` if data is available, `Ok(None)` if no data
    /// yet (would block), or `Err(Eof)` if the channel is permanently closed.
    pub fn try_recv(&self) -> Result<Option<Body>, RtChannelError> {
        let mut ptr: *mut u8 = core::ptr::null_mut();
        let mut len: u32 = 0;
        let rc = unsafe { (self.try_recv_fn)(self.ctx, &mut ptr, &mut len) };
        match rc {
            0 => self.decode_and_free(ptr, len).map(Some),
            -1 => Ok(None),                // would block
            _ => Err(RtChannelError::Eof), // -2 = EOF
        }
    }

    fn decode_and_free(&self, ptr: *mut u8, len: u32) -> Result<Body, RtChannelError> {
        let bytes = unsafe { core::slice::from_raw_parts(ptr, len as usize) };
        let result = crate::codec::decode_spite(bytes);
        unsafe { (self.host_free)(ptr, len) };
        match result {
            Ok(spite) => spite.body.ok_or(RtChannelError::NoBody),
            Err(e) => Err(RtChannelError::Decode(e.to_string())),
        }
    }
}

// ── Error / Result types ────────────────────────────────────────────────────

/// Channel operation error.
#[derive(Debug)]
pub enum RtChannelError {
    /// Host closed the output channel (send failed).
    Closed,
    /// No more input (recv returned EOF).
    Eof,
    /// Received a Spite with no Body.
    NoBody,
    /// Protobuf decode error.
    Decode(String),
}

impl core::fmt::Display for RtChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Closed => write!(f, "channel closed"),
            Self::Eof => write!(f, "end of input"),
            Self::NoBody => write!(f, "received spite with no body"),
            Self::Decode(e) => write!(f, "decode error: {}", e),
        }
    }
}

/// Module execution result.
pub enum RtResult {
    /// Module completed successfully. Body is the final output.
    Done(Body),
    /// Module encountered an error.
    Error(String),
}

// Convenience: allow `ch.recv()?` to propagate into RtResult::Error
impl From<RtChannelError> for RtResult {
    fn from(e: RtChannelError) -> Self {
        RtResult::Error(e.to_string())
    }
}

// ── RtModule trait ──────────────────────────────────────────────────────────

/// Trait implemented by each runtime module.
///
/// Unlike the host-side `Module` trait, this is fully synchronous and blocking.
/// The module controls its own execution flow via `channel.send()` / `recv()`.
pub trait RtModule: Send + 'static {
    /// Module name (static string matching the command name).
    fn name() -> &'static str
    where
        Self: Sized;

    /// Create a new instance.
    fn new() -> Self
    where
        Self: Sized;

    /// Run the module with full bidirectional channel access.
    ///
    /// The module can:
    /// - `channel.recv()` to pull input from the host (blocking)
    /// - `channel.send()` to push output to the host
    /// - `channel.try_recv()` to poll for input without blocking
    /// - Return `RtResult::Done(body)` when finished
    fn run(&mut self, task_id: u32, channel: &RtChannel) -> RtResult;
}

// ── Type erasure (for macro internals) ──────────────────────────────────────

#[doc(hidden)]
pub trait ErasedRtModule: Send {
    fn run(&mut self, task_id: u32, channel: &RtChannel) -> RtResult;
}

impl<T: RtModule> ErasedRtModule for T {
    fn run(&mut self, task_id: u32, channel: &RtChannel) -> RtResult {
        RtModule::run(self, task_id, channel)
    }
}

/// Descriptor for a registered module (used by the macro).
pub struct RtModuleDescriptor {
    pub name_fn: fn() -> &'static str,
    pub constructor: fn() -> Box<dyn ErasedRtModule>,
}

// ── Registration macro ──────────────────────────────────────────────────────

/// Generate all required C ABI exports for a set of modules.
///
/// Exports 7 `extern "C"` functions: `rt_abi_version`, `rt_module_count`,
/// `rt_module_name`, `rt_module_create`, `rt_module_destroy`,
/// `rt_module_run`, `rt_free`.
///
/// Supports `#[cfg(...)]` on each module for conditional compilation:
/// ```ignore
/// register_rt_modules!(
///     #[cfg(feature = "pwd")] fs::pwd::Pwd,
///     #[cfg(feature = "whoami")] sys::whoami::Whoami,
/// );
/// ```
#[macro_export]
macro_rules! register_rt_modules {
    ($($(#[$meta:meta])* $module:ty),+ $(,)?) => {
        static _RT_MODULE_REGISTRY: &[$crate::module_sdk::RtModuleDescriptor] = &[
            $(
                $(#[$meta])*
                $crate::module_sdk::RtModuleDescriptor {
                    name_fn: <$module as $crate::module_sdk::RtModule>::name,
                    constructor: || {
                        Box::new(<$module as $crate::module_sdk::RtModule>::new())
                    },
                },
            )+
        ];

        #[no_mangle]
        pub extern "C" fn rt_abi_version() -> u32 {
            $crate::abi::RT_ABI_VERSION
        }

        #[no_mangle]
        pub extern "C" fn rt_module_count() -> u32 {
            _RT_MODULE_REGISTRY.len() as u32
        }

        #[no_mangle]
        pub extern "C" fn rt_module_name(index: u32) -> $crate::abi::RtBuffer {
            if (index as usize) >= _RT_MODULE_REGISTRY.len() {
                return $crate::abi::RtBuffer::empty();
            }
            let name = (_RT_MODULE_REGISTRY[index as usize].name_fn)();
            $crate::abi::RtBuffer::from_vec(name.as_bytes().to_vec())
        }

        #[no_mangle]
        pub extern "C" fn rt_module_create(
            name_ptr: *const u8,
            name_len: u32,
        ) -> *mut $crate::abi::RtModuleHandle {
            if name_ptr.is_null() || name_len == 0 {
                return core::ptr::null_mut();
            }
            let name = unsafe {
                match core::str::from_utf8(
                    core::slice::from_raw_parts(name_ptr, name_len as usize)
                ) {
                    Ok(s) => s,
                    Err(_) => return core::ptr::null_mut(),
                }
            };
            for desc in _RT_MODULE_REGISTRY.iter() {
                if (desc.name_fn)() == name {
                    let module = (desc.constructor)();
                    let boxed = Box::new(module);
                    return Box::into_raw(boxed) as *mut $crate::abi::RtModuleHandle;
                }
            }
            core::ptr::null_mut()
        }

        #[no_mangle]
        pub extern "C" fn rt_module_destroy(handle: *mut $crate::abi::RtModuleHandle) {
            if !handle.is_null() {
                unsafe {
                    let _ = Box::from_raw(
                        handle as *mut Box<dyn $crate::module_sdk::ErasedRtModule>
                    );
                }
            }
        }

        #[no_mangle]
        pub extern "C" fn rt_module_run(
            handle: *mut $crate::abi::RtModuleHandle,
            task_id: u32,
            ctx: *mut core::ffi::c_void,
            send_fn: $crate::abi::RtSendFn,
            recv_fn: $crate::abi::RtRecvFn,
            try_recv_fn: $crate::abi::RtTryRecvFn,
            host_free: $crate::abi::RtHostFreeFn,
            final_out: *mut $crate::abi::RtBuffer,
        ) -> $crate::abi::RtStatus {
            use $crate::abi::{RtBuffer, RtStatus};

            if handle.is_null() || final_out.is_null() {
                return RtStatus::Error;
            }

            let module = unsafe {
                &mut *(handle as *mut Box<dyn $crate::module_sdk::ErasedRtModule>)
            };

            let channel = unsafe {
                $crate::module_sdk::RtChannel::from_raw(
                    task_id, ctx, send_fn, recv_fn, try_recv_fn, host_free,
                )
            };

            let (status, buf) = match module.run(task_id, &channel) {
                $crate::module_sdk::RtResult::Done(body) => {
                    let bytes = $crate::codec::encode_body(task_id, body);
                    (RtStatus::Done, RtBuffer::from_vec(bytes))
                }
                $crate::module_sdk::RtResult::Error(msg) => {
                    (RtStatus::Error, RtBuffer::from_vec(msg.into_bytes()))
                }
            };

            unsafe { *final_out = buf; }
            status
        }

        #[no_mangle]
        pub extern "C" fn rt_free(buf: $crate::abi::RtBuffer) {
            unsafe { $crate::abi::rt_buffer_from_vec_free(buf); }
        }
    };
}
