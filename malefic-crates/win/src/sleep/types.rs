#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code
)]

use core::ffi::c_void;
use core::ptr::null_mut;

// ── Constants ────────────────────────────────────────────────────────

pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READ: u64 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u64 = 0x40;
pub const MEM_COMMIT: u32 = 0x00001000;
pub const MEM_RESERVE: u32 = 0x00002000;
pub const CONTEXT_FULL: u32 = 0x00010007;
pub const THREAD_ALL_ACCESS: u32 = 0x001F03FF;
pub const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;
pub const VM_LOCK_1: u32 = 0x0001;

pub const EVENT_ALL_ACCESS: u32 = 0x001F0003;

pub const HEAP_GROWABLE: u32 = 0x00000002;

// ── Basic Windows types ──────────────────────────────────────────────

pub type NTSTATUS = i32;
pub type HANDLE = *mut c_void;

pub const STATUS_UNSUCCESSFUL: NTSTATUS = -1_073_741_823i32; // 0xC0000001

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LARGE_INTEGER {
    pub QuadPart: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum EVENT_TYPE {
    SynchronizationEvent = 0,
    NotificationEvent = 1,
}

// ── Utility functions ────────────────────────────────────────────────

#[inline]
pub fn nt_current_process() -> HANDLE {
    -1isize as *mut c_void
}

#[inline]
pub fn nt_current_thread() -> HANDLE {
    -2isize as *mut c_void
}

#[inline]
pub fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

// ── CONTEXT (x86_64 Windows ABI) ────────────────────────────────────
//
// Must be exactly 1232 bytes with 16-byte alignment.
// Layout matches the Windows AMD64 CONTEXT structure.

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct CONTEXT {
    // Register parameter home addresses
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,

    // Control flags
    pub ContextFlags: u32,
    pub MxCsr: u32,

    // Segment registers
    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: u32,

    // Debug registers
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,

    // Integer registers
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,

    // Program counter
    pub Rip: u64,

    // Floating point / XSAVE area (512 bytes)
    pub FltSave: XSAVE_FORMAT,

    // Vector registers (26 x M128A = 416 bytes)
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,

    // Special debug control registers
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

// Verify the size at compile time
const _: () = assert!(core::mem::size_of::<CONTEXT>() == 1232);

impl Default for CONTEXT {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}

impl Default for M128A {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct XSAVE_FORMAT {
    pub ControlWord: u16,
    pub StatusWord: u16,
    pub TagWord: u8,
    pub Reserved1: u8,
    pub ErrorOpcode: u16,
    pub ErrorOffset: u32,
    pub ErrorSelector: u16,
    pub Reserved2: u16,
    pub DataOffset: u32,
    pub DataSelector: u16,
    pub Reserved3: u16,
    pub MxCsr: u32,
    pub MxCsr_Mask: u32,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 16],
    pub Reserved4: [u8; 96],
}

impl Default for XSAVE_FORMAT {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

// ── Thread Pool structures ───────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TP_CALLBACK_ENVIRON_V3 {
    pub Version: u32,
    pub Pool: *mut c_void,
    pub CleanupGroup: *mut c_void,
    pub CleanupGroupCancelCallback: *mut c_void,
    pub RaceDll: *mut c_void,
    pub ActivationContext: isize,
    pub FinalizationCallback: *mut c_void,
    pub u: TP_CALLBACK_ENVIRON_V3_0,
    pub CallbackPriority: i32,
    pub Size: u32,
}

impl Default for TP_CALLBACK_ENVIRON_V3 {
    fn default() -> Self {
        Self {
            Version: 3,
            Pool: null_mut(),
            CleanupGroup: null_mut(),
            CleanupGroupCancelCallback: null_mut(),
            RaceDll: null_mut(),
            ActivationContext: 0,
            FinalizationCallback: null_mut(),
            u: TP_CALLBACK_ENVIRON_V3_0 { Flags: 0 },
            CallbackPriority: 1,
            Size: core::mem::size_of::<TP_CALLBACK_ENVIRON_V3>() as u32,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TP_CALLBACK_ENVIRON_V3_0 {
    pub Flags: u32,
    pub s: TP_CALLBACK_ENVIRON_V3_0_0,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TP_CALLBACK_ENVIRON_V3_0_0 {
    pub _bitfield: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct TP_POOL_STACK_INFORMATION {
    pub StackReserve: usize,
    pub StackCommit: usize,
}

// ── Heap walking structures ──────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RTL_HEAP_WALK_ENTRY {
    pub DataAddress: *mut c_void,
    pub DataSize: usize,
    pub OverheadBytes: u8,
    pub SegmentIndex: u8,
    pub Flags: u16,
    pub Anonymous: RTL_HEAP_WALK_ENTRY_0,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union RTL_HEAP_WALK_ENTRY_0 {
    pub Block: RTL_HEAP_WALK_ENTRY_0_0,
    pub Segment: RTL_HEAP_WALK_ENTRY_0_0_0,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RTL_HEAP_WALK_ENTRY_0_0 {
    pub Settable: usize,
    pub TagIndex: u16,
    pub AllocatorBackTraceIndex: u16,
    pub Reserved: [u16; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RTL_HEAP_WALK_ENTRY_0_0_0 {
    pub CommittedSize: u32,
    pub UnCommittedSize: u32,
    pub FirstEntry: *mut c_void,
    pub LastEntry: *mut c_void,
}

// ── Function pointer types ───────────────────────────────────────────

pub type LPFIBER_START_ROUTINE = Option<unsafe extern "system" fn(lpFiberParameter: *mut c_void)>;

pub type ConvertThreadToFiberFn =
    unsafe extern "system" fn(lpParameter: *mut c_void) -> *mut c_void;
pub type ConvertFiberToThreadFn = unsafe extern "system" fn() -> i32;
pub type SwitchToFiberFn = unsafe extern "system" fn(lpFiber: *mut c_void);
pub type DeleteFiberFn = unsafe extern "system" fn(lpFiber: *mut c_void);
pub type CreateFiberFn = unsafe extern "system" fn(
    dwStackSize: usize,
    lpStartAddress: LPFIBER_START_ROUTINE,
    lpParameter: *const c_void,
) -> *mut c_void;

pub type CloseThreadpoolFn = unsafe extern "system" fn(Pool: *mut c_void) -> NTSTATUS;

pub type TpAllocPoolFn =
    unsafe extern "system" fn(PoolReturn: *mut *mut c_void, Reserved: *mut c_void) -> NTSTATUS;

pub type TpSetPoolMaxThreadsFn = unsafe extern "system" fn(Pool: *mut c_void, MaxThreads: u32);

pub type TpSetPoolMinThreadsFn =
    unsafe extern "system" fn(Pool: *mut c_void, MinThreads: u32) -> NTSTATUS;

pub type TpSetWaitFn =
    unsafe extern "system" fn(Wait: *mut c_void, Handle: *mut c_void, Timeout: *mut LARGE_INTEGER);

pub type TpAllocFn = unsafe extern "system" fn(
    Timer: *mut *mut c_void,
    Callback: *mut c_void,
    Context: *mut c_void,
    CallbackEnviron: *mut TP_CALLBACK_ENVIRON_V3,
) -> NTSTATUS;

pub type TpSetPoolStackInformationFn = unsafe extern "system" fn(
    Pool: *mut c_void,
    PoolStackInformation: *mut TP_POOL_STACK_INFORMATION,
) -> NTSTATUS;

pub type TpSetTimerFn = unsafe extern "system" fn(
    Timer: *mut c_void,
    DueTime: *mut LARGE_INTEGER,
    Period: u32,
    WindowLength: u32,
);

pub type NtCloseFn = unsafe extern "system" fn(Handle: HANDLE) -> NTSTATUS;

pub type NtSetEventFn =
    unsafe extern "system" fn(hEvent: *mut c_void, PreviousState: *mut i32) -> NTSTATUS;

pub type NtCreateEventFn = unsafe extern "system" fn(
    EventHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut c_void,
    EventType: EVENT_TYPE,
    InitialState: u8,
) -> NTSTATUS;

pub type NtWaitForSingleObjectFn =
    unsafe extern "system" fn(Handle: HANDLE, Alertable: u8, Timeout: *mut i32) -> NTSTATUS;

pub type NtSignalAndWaitForSingleObjectFn = unsafe extern "system" fn(
    SignalHandle: HANDLE,
    WaitHandle: HANDLE,
    Alertable: u8,
    Timeout: *mut LARGE_INTEGER,
) -> NTSTATUS;

pub type NtAlertResumeThreadFn =
    unsafe extern "system" fn(ThreadHandle: HANDLE, PreviousSuspendCount: *mut u32) -> NTSTATUS;

pub type NtQueueApcThreadFn = unsafe extern "system" fn(
    ThreadHandle: HANDLE,
    ApcRoutine: *mut c_void,
    ApcArgument1: *mut c_void,
    ApcArgument2: *mut c_void,
    ApcArgument3: *mut c_void,
) -> NTSTATUS;

pub type NtDuplicateObjectFn = unsafe extern "system" fn(
    SourceProcessHandle: HANDLE,
    SourceHandle: HANDLE,
    TargetProcessHandle: HANDLE,
    TargetHandle: *mut HANDLE,
    DesiredAccess: u32,
    HandleAttributes: u32,
    Options: u32,
) -> NTSTATUS;

pub type NtLockVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut *mut c_void,
    RegionSize: *mut usize,
    MapType: u32,
) -> NTSTATUS;

pub type RtlWalkHeapFn =
    unsafe extern "system" fn(HeapHandle: *mut c_void, Entry: *mut RTL_HEAP_WALK_ENTRY) -> NTSTATUS;

pub type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut *mut c_void,
    ZeroBits: usize,
    RegionSize: *mut usize,
    AllocationType: u32,
    Protect: u32,
) -> NTSTATUS;

pub type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
    ProcessHandle: *mut c_void,
    BaseAddress: *mut *mut c_void,
    RegionSize: *mut usize,
    NewProtect: u32,
    OldProtect: *mut u32,
) -> NTSTATUS;

pub type NtCreateThreadExFn = unsafe extern "system" fn(
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
) -> NTSTATUS;

pub type GetProcessHeapFn = unsafe extern "system" fn() -> *mut c_void;

pub type RtlCreateHeapFn = unsafe extern "system" fn(
    Flags: u32,
    HeapBase: *mut c_void,
    ReserveSize: usize,
    CommitSize: usize,
    Lock: *mut c_void,
    Parameters: *mut c_void,
) -> *mut c_void;

pub type RtlAllocateHeapFn =
    unsafe extern "system" fn(HeapHandle: *mut c_void, Flags: u32, Size: usize) -> *mut c_void;

pub type RtlFreeHeapFn =
    unsafe extern "system" fn(HeapHandle: *mut c_void, Flags: u32, BaseAddress: *mut c_void) -> i8;
