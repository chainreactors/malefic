//! malefic-3rd-template — Third-party module DLL using the runtime C ABI protocol.
//!
//! Exports 7 `extern "C"` functions (rt_abi_version, rt_module_count, etc.)
//! for cross-version-safe hot loading.

use malefic_runtime::abi::{RtBuffer, RtModuleHandle, RtStatus, RT_ABI_VERSION};
use malefic_runtime::abi::{RtSendFn, RtRecvFn, RtTryRecvFn, RtHostFreeFn};
use malefic_runtime::module_sdk::{RtModule, RtChannel, ErasedRtModule, RtModuleDescriptor};
use malefic_runtime::codec;

// ── Registry ────────────────────────────────────────────────────────────────

/// A runtime-named module descriptor — the name comes from FFI (CModuleName etc.)
/// rather than from the static RtModule::name().
struct RuntimeNamedModule {
    name: String,
    module: Box<dyn ErasedRtModule>,
}

fn build_registry() -> Vec<RtModuleDescriptor> {
    // We can't use RtModuleDescriptor directly because the names are
    // runtime-determined (from FFI calls like CModuleName, GoModuleName).
    // Instead, we build an intermediate list then convert.
    //
    // For now, use name_fn that returns the static trait name.
    // The actual FFI-determined names are set via the modules themselves.
    let mut v: Vec<RtModuleDescriptor> = Vec::new();

    #[cfg(feature = "rust_module")]
    v.push(RtModuleDescriptor {
        name_fn: malefic_3rd_rust::RustModule::name,
        constructor: || Box::new(malefic_3rd_rust::RustModule::new()),
    });

    #[cfg(feature = "golang_module")]
    v.push(RtModuleDescriptor {
        name_fn: malefic_3rd_go::GolangModule::name,
        constructor: || Box::new(malefic_3rd_go::GolangModule::new()),
    });

    #[cfg(feature = "c_module")]
    v.push(RtModuleDescriptor {
        name_fn: malefic_3rd_c::CModule::name,
        constructor: || Box::new(malefic_3rd_c::CModule::new()),
    });

    #[cfg(feature = "zig_module")]
    v.push(RtModuleDescriptor {
        name_fn: malefic_3rd_zig::ZigModule::name,
        constructor: || Box::new(malefic_3rd_zig::ZigModule::new()),
    });

    #[cfg(feature = "nim_module")]
    v.push(RtModuleDescriptor {
        name_fn: malefic_3rd_nim::NimModule::name,
        constructor: || Box::new(malefic_3rd_nim::NimModule::new()),
    });

    v
}

fn get_registry() -> &'static [RtModuleDescriptor] {
    use std::sync::OnceLock;
    static REGISTRY: OnceLock<Vec<RtModuleDescriptor>> = OnceLock::new();
    REGISTRY.get_or_init(build_registry)
}

// ── C ABI Exports ───────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn rt_abi_version() -> u32 {
    RT_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn rt_module_count() -> u32 {
    get_registry().len() as u32
}

#[no_mangle]
pub extern "C" fn rt_module_name(index: u32) -> RtBuffer {
    let registry = get_registry();
    if (index as usize) >= registry.len() {
        return RtBuffer::empty();
    }
    let name = (registry[index as usize].name_fn)();
    RtBuffer::from_vec(name.as_bytes().to_vec())
}

#[no_mangle]
pub extern "C" fn rt_module_create(
    name_ptr: *const u8,
    name_len: u32,
) -> *mut RtModuleHandle {
    if name_ptr.is_null() || name_len == 0 {
        return core::ptr::null_mut();
    }
    let name = unsafe {
        match core::str::from_utf8(core::slice::from_raw_parts(name_ptr, name_len as usize)) {
            Ok(s) => s,
            Err(_) => return core::ptr::null_mut(),
        }
    };
    for desc in get_registry() {
        if (desc.name_fn)() == name {
            let module = (desc.constructor)();
            let boxed = Box::new(module);
            return Box::into_raw(boxed) as *mut RtModuleHandle;
        }
    }
    core::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn rt_module_destroy(handle: *mut RtModuleHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle as *mut Box<dyn ErasedRtModule>);
        }
    }
}

#[no_mangle]
pub extern "C" fn rt_module_run(
    handle: *mut RtModuleHandle,
    task_id: u32,
    ctx: *mut core::ffi::c_void,
    send_fn: RtSendFn,
    recv_fn: RtRecvFn,
    try_recv_fn: RtTryRecvFn,
    host_free: RtHostFreeFn,
    final_out: *mut RtBuffer,
) -> RtStatus {
    if handle.is_null() || final_out.is_null() {
        return RtStatus::Error;
    }

    let module = unsafe { &mut *(handle as *mut Box<dyn ErasedRtModule>) };

    let channel = unsafe {
        RtChannel::from_raw(task_id, ctx, send_fn, recv_fn, try_recv_fn, host_free)
    };

    let (status, buf) = match module.run(task_id, &channel) {
        malefic_runtime::module_sdk::RtResult::Done(body) => {
            let bytes = codec::encode_body(task_id, body);
            (RtStatus::Done, RtBuffer::from_vec(bytes))
        }
        malefic_runtime::module_sdk::RtResult::Error(msg) => {
            (RtStatus::Error, RtBuffer::from_vec(msg.into_bytes()))
        }
    };

    unsafe { *final_out = buf; }
    status
}

#[no_mangle]
pub extern "C" fn rt_free(buf: RtBuffer) {
    unsafe { malefic_runtime::abi::rt_buffer_from_vec_free(buf); }
}
