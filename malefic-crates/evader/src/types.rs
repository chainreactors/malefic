//! Windows type definitions and constants for evader modules
//!
//! Subset of Win32 ABI definitions used by the evasion techniques.
//! Duplicated from malefic-starship/src/types.rs (stable Win32 ABI).

use core::ffi::c_void;

// ============================================================
// Memory management constants
// ============================================================
pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_RELEASE: u32 = 0x8000;
pub const MEM_PRIVATE: u32 = 0x20000;

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// ============================================================
// Process / thread access rights
// ============================================================
pub const PROCESS_ALL_ACCESS: u32 = 0x001F0FFF;
pub const THREAD_ALL_ACCESS: u32 = 0x001F03FF;

// ============================================================
// Thread creation flags
// ============================================================
pub const CREATE_SUSPENDED: u32 = 0x00000004;
pub const CREATE_NO_WINDOW: u32 = 0x08000000;

// ============================================================
// Wait / synchronisation
// ============================================================
pub const INFINITE: u32 = 0xFFFFFFFF;
pub const WAIT_TIMEOUT: u32 = 258;

// ============================================================
// Toolhelp snapshot flags
// ============================================================
pub const TH32CS_SNAPTHREAD: u32 = 0x00000004;
pub const TH32CS_SNAPPROCESS: u32 = 0x00000002;

// ============================================================
// File I/O constants
// ============================================================
pub const FILE_GENERIC_READ: u32 = 0x00120089;
pub const FILE_SHARE_READ: u32 = 0x00000001;
pub const OPEN_EXISTING: u32 = 3;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;
pub const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;

// ============================================================
// Exception / debug constants
// ============================================================
pub const CONTEXT_DEBUG_REGISTERS: u32 = 0x00010010;
pub const CONTEXT_FULL: u32 = 0x0010001F;
pub const CONTEXT_ALL: u32 = 0x0010003F;
pub const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

// ============================================================
// UI / message constants
// ============================================================
pub const LVM_SORTITEMS: u32 = 0x1030;

// ============================================================
// Structures
// ============================================================

#[repr(C)]
pub struct THREADENTRY32 {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ThreadID: u32,
    pub th32OwnerProcessID: u32,
    pub tpBasePri: i32,
    pub tpDeltaPri: i32,
    pub dwFlags: u32,
}

#[repr(C)]
pub struct STARTUPINFOA {
    pub cb: u32,
    pub lpReserved: *mut u8,
    pub lpDesktop: *mut u8,
    pub lpTitle: *mut u8,
    pub dwX: u32,
    pub dwY: u32,
    pub dwXSize: u32,
    pub dwYSize: u32,
    pub dwXCountChars: u32,
    pub dwYCountChars: u32,
    pub dwFillAttribute: u32,
    pub dwFlags: u32,
    pub wShowWindow: u16,
    pub cbReserved2: u16,
    pub lpReserved2: *mut u8,
    pub hStdInput: *mut c_void,
    pub hStdOutput: *mut c_void,
    pub hStdError: *mut c_void,
}

#[repr(C)]
pub struct PROCESS_INFORMATION {
    pub hProcess: *mut c_void,
    pub hThread: *mut c_void,
    pub dwProcessId: u32,
    pub dwThreadId: u32,
}

#[repr(C)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: u32,
    pub lpSecurityDescriptor: *mut c_void,
    pub bInheritHandle: i32,
}

/// CONTEXT struct (x86_64) — only the fields commonly used by loaders.
/// Full CONTEXT is 1232 bytes on x86_64; we use a byte-array for the rest.
#[cfg(target_arch = "x86_64")]
#[repr(C, align(16))]
pub struct CONTEXT {
    pub data: [u8; 1232],
}

#[cfg(target_arch = "x86_64")]
impl CONTEXT {
    pub fn new() -> Self {
        Self { data: [0u8; 1232] }
    }

    fn read_u32(&self, offset: usize) -> u32 {
        let mut bytes = [0u8; 4];
        if let Some(slice) = self.data.get(offset..offset.saturating_add(4)) {
            bytes.copy_from_slice(slice);
        }
        u32::from_ne_bytes(bytes)
    }

    fn read_u64(&self, offset: usize) -> u64 {
        let mut bytes = [0u8; 8];
        if let Some(slice) = self.data.get(offset..offset.saturating_add(8)) {
            bytes.copy_from_slice(slice);
        }
        u64::from_ne_bytes(bytes)
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        if let Some(slice) = self.data.get_mut(offset..offset.saturating_add(4)) {
            slice.copy_from_slice(&value.to_ne_bytes());
        }
    }

    fn write_u64(&mut self, offset: usize, value: u64) {
        if let Some(slice) = self.data.get_mut(offset..offset.saturating_add(8)) {
            slice.copy_from_slice(&value.to_ne_bytes());
        }
    }

    /// ContextFlags at offset 0x30
    pub fn context_flags(&self) -> u32 {
        self.read_u32(0x30)
    }
    pub fn set_context_flags(&mut self, flags: u32) {
        self.write_u32(0x30, flags);
    }

    /// Rip at offset 0xF8
    pub fn rip(&self) -> u64 {
        self.read_u64(0xF8)
    }
    pub fn set_rip(&mut self, val: u64) {
        self.write_u64(0xF8, val);
    }

    /// Rsp at offset 0x98
    pub fn rsp(&self) -> u64 {
        self.read_u64(0x98)
    }
    pub fn set_rsp(&mut self, val: u64) {
        self.write_u64(0x98, val);
    }

    /// Dr0-Dr3 at offsets 0x48, 0x50, 0x58, 0x60
    pub fn dr(&self, idx: usize) -> u64 {
        let off = 0x48 + idx * 8;
        self.read_u64(off)
    }
    pub fn set_dr(&mut self, idx: usize, val: u64) {
        let off = 0x48 + idx * 8;
        self.write_u64(off, val);
    }

    /// Dr6 at offset 0x68
    pub fn dr6(&self) -> u64 {
        self.read_u64(0x68)
    }
    pub fn set_dr6(&mut self, val: u64) {
        self.write_u64(0x68, val);
    }

    /// Dr7 at offset 0x70
    pub fn dr7(&self) -> u64 {
        self.read_u64(0x70)
    }
    pub fn set_dr7(&mut self, val: u64) {
        self.write_u64(0x70, val);
    }
}

#[cfg(target_arch = "x86")]
#[repr(C)]
pub struct CONTEXT {
    pub data: [u8; 716],
}

#[cfg(target_arch = "x86")]
impl CONTEXT {
    pub fn new() -> Self {
        Self { data: [0u8; 716] }
    }

    fn read_u32(&self, offset: usize) -> u32 {
        let mut bytes = [0u8; 4];
        if let Some(slice) = self.data.get(offset..offset.saturating_add(4)) {
            bytes.copy_from_slice(slice);
        }
        u32::from_ne_bytes(bytes)
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        if let Some(slice) = self.data.get_mut(offset..offset.saturating_add(4)) {
            slice.copy_from_slice(&value.to_ne_bytes());
        }
    }

    pub fn context_flags(&self) -> u32 {
        self.read_u32(0x00)
    }
    pub fn set_context_flags(&mut self, flags: u32) {
        self.write_u32(0x00, flags);
    }

    /// Eip at offset 0xB8
    pub fn eip(&self) -> u32 {
        self.read_u32(0xB8)
    }
    pub fn set_eip(&mut self, val: u32) {
        self.write_u32(0xB8, val);
    }
}

/// EXCEPTION_POINTERS (used by VEH callbacks)
#[repr(C)]
pub struct EXCEPTION_POINTERS {
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ContextRecord: *mut CONTEXT,
}

#[repr(C)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode: u32,
    pub ExceptionFlags: u32,
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ExceptionAddress: *mut c_void,
    pub NumberParameters: u32,
    pub ExceptionInformation: [usize; 15],
}

/// MEMORY_BASIC_INFORMATION (used by VirtualQuery)
#[repr(C)]
pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress: *mut c_void,
    pub AllocationBase: *mut c_void,
    pub AllocationProtect: u32,
    #[cfg(target_arch = "x86_64")]
    pub PartitionId: u16,
    pub RegionSize: usize,
    pub State: u32,
    pub Protect: u32,
    pub Type: u32,
}
