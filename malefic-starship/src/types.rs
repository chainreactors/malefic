//! Windows type definitions and constants for loaders
//!
//! Centralizes all Windows constants and struct definitions
//! so individual loaders don't need the `windows` crate.

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

    /// ContextFlags at offset 0x30
    pub fn context_flags(&self) -> u32 {
        u32::from_ne_bytes(self.data[0x30..0x34].try_into().unwrap())
    }
    pub fn set_context_flags(&mut self, flags: u32) {
        self.data[0x30..0x34].copy_from_slice(&flags.to_ne_bytes());
    }

    /// Rip at offset 0xF8
    pub fn rip(&self) -> u64 {
        u64::from_ne_bytes(self.data[0xF8..0x100].try_into().unwrap())
    }
    pub fn set_rip(&mut self, val: u64) {
        self.data[0xF8..0x100].copy_from_slice(&val.to_ne_bytes());
    }

    /// Rsp at offset 0x98
    pub fn rsp(&self) -> u64 {
        u64::from_ne_bytes(self.data[0x98..0xA0].try_into().unwrap())
    }
    pub fn set_rsp(&mut self, val: u64) {
        self.data[0x98..0xA0].copy_from_slice(&val.to_ne_bytes());
    }

    /// Dr0-Dr3 at offsets 0x48, 0x50, 0x58, 0x60
    pub fn dr(&self, idx: usize) -> u64 {
        let off = 0x48 + idx * 8;
        u64::from_ne_bytes(self.data[off..off + 8].try_into().unwrap())
    }
    pub fn set_dr(&mut self, idx: usize, val: u64) {
        let off = 0x48 + idx * 8;
        self.data[off..off + 8].copy_from_slice(&val.to_ne_bytes());
    }

    /// Dr6 at offset 0x68
    pub fn dr6(&self) -> u64 {
        u64::from_ne_bytes(self.data[0x68..0x70].try_into().unwrap())
    }
    pub fn set_dr6(&mut self, val: u64) {
        self.data[0x68..0x70].copy_from_slice(&val.to_ne_bytes());
    }

    /// Dr7 at offset 0x70
    pub fn dr7(&self) -> u64 {
        u64::from_ne_bytes(self.data[0x70..0x78].try_into().unwrap())
    }
    pub fn set_dr7(&mut self, val: u64) {
        self.data[0x70..0x78].copy_from_slice(&val.to_ne_bytes());
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

    pub fn context_flags(&self) -> u32 {
        u32::from_ne_bytes(self.data[0x00..0x04].try_into().unwrap())
    }
    pub fn set_context_flags(&mut self, flags: u32) {
        self.data[0x00..0x04].copy_from_slice(&flags.to_ne_bytes());
    }

    /// Eip at offset 0xB8
    pub fn eip(&self) -> u32 {
        u32::from_ne_bytes(self.data[0xB8..0xBC].try_into().unwrap())
    }
    pub fn set_eip(&mut self, val: u32) {
        self.data[0xB8..0xBC].copy_from_slice(&val.to_ne_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    // ── Constant value tests ───────────────────────────────────────────────
    #[test]
    fn test_memory_constants() {
        assert_eq!(MEM_COMMIT,  0x1000);
        assert_eq!(MEM_RESERVE, 0x2000);
        assert_eq!(MEM_RELEASE, 0x8000);
        assert_eq!(MEM_PRIVATE, 0x20000);
    }

    #[test]
    fn test_page_protection_constants() {
        assert_eq!(PAGE_NOACCESS,           0x01);
        assert_eq!(PAGE_READWRITE,          0x04);
        assert_eq!(PAGE_EXECUTE_READ,       0x20);
        assert_eq!(PAGE_EXECUTE_READWRITE,  0x40);
    }

    #[test]
    fn test_access_rights_constants() {
        assert_eq!(PROCESS_ALL_ACCESS, 0x001F0FFF);
        assert_eq!(THREAD_ALL_ACCESS,  0x001F03FF);
    }

    #[test]
    fn test_thread_constants() {
        assert_eq!(CREATE_SUSPENDED, 0x00000004);
        assert_eq!(CREATE_NO_WINDOW, 0x08000000);
    }

    #[test]
    fn test_wait_constants() {
        assert_eq!(INFINITE, 0xFFFFFFFF);
        assert_eq!(WAIT_TIMEOUT, 258);
    }

    #[test]
    fn test_exception_constants() {
        assert_eq!(CONTEXT_DEBUG_REGISTERS, 0x00010010);
        assert_eq!(CONTEXT_FULL,            0x0010001F);
        assert_eq!(CONTEXT_ALL,             0x0010003F);
        assert_eq!(EXCEPTION_SINGLE_STEP,   0x80000004);
        assert_eq!(EXCEPTION_CONTINUE_EXECUTION, -1);
        assert_eq!(EXCEPTION_CONTINUE_SEARCH,     0);
    }

    #[test]
    fn test_file_constants() {
        assert_eq!(FILE_GENERIC_READ,    0x00120089);
        assert_eq!(FILE_SHARE_READ,      0x00000001);
        assert_eq!(OPEN_EXISTING,        3);
        assert_eq!(FILE_ATTRIBUTE_NORMAL, 0x00000080);
    }

    #[test]
    fn test_toolhelp_constants() {
        assert_eq!(TH32CS_SNAPTHREAD,  0x00000004);
        assert_eq!(TH32CS_SNAPPROCESS, 0x00000002);
    }

    // ── Struct size tests ──────────────────────────────────────────────────
    #[test]
    fn test_threadentry32_size() {
        // THREADENTRY32 is 28 bytes (7 × u32/i32)
        assert_eq!(size_of::<THREADENTRY32>(), 28);
    }

    #[test]
    fn test_process_information_size() {
        // Two handles (8 bytes each on x64) + two u32 = 24 bytes
        #[cfg(target_arch = "x86_64")]
        assert_eq!(size_of::<PROCESS_INFORMATION>(), 24);
    }

    #[test]
    fn test_security_attributes_size() {
        #[cfg(target_arch = "x86_64")]
        assert_eq!(size_of::<SECURITY_ATTRIBUTES>(), 24);
    }

    // ── CONTEXT getter/setter tests ────────────────────────────────────────
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_context_new_is_zeroed() {
        let ctx = CONTEXT::new();
        assert!(ctx.data.iter().all(|&b| b == 0));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_context_size() {
        assert_eq!(size_of::<CONTEXT>(), 1232);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_context_flags_roundtrip() {
        let mut ctx = CONTEXT::new();
        ctx.set_context_flags(CONTEXT_ALL);
        assert_eq!(ctx.context_flags(), CONTEXT_ALL);
        ctx.set_context_flags(CONTEXT_DEBUG_REGISTERS);
        assert_eq!(ctx.context_flags(), CONTEXT_DEBUG_REGISTERS);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_context_rip_roundtrip() {
        let mut ctx = CONTEXT::new();
        ctx.set_rip(0xDEADBEEF_CAFEBABE);
        assert_eq!(ctx.rip(), 0xDEADBEEF_CAFEBABE);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_context_rsp_roundtrip() {
        let mut ctx = CONTEXT::new();
        ctx.set_rsp(0x00007FFE_12345678);
        assert_eq!(ctx.rsp(), 0x00007FFE_12345678);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_context_dr_registers() {
        let mut ctx = CONTEXT::new();
        for i in 0..4 {
            let val = 0x1111_1111 * (i as u64 + 1);
            ctx.set_dr(i, val);
            assert_eq!(ctx.dr(i), val, "DR{} mismatch", i);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_context_dr6_dr7_roundtrip() {
        let mut ctx = CONTEXT::new();
        ctx.set_dr6(0xFFFF0FF0);
        ctx.set_dr7(0x00000401);
        assert_eq!(ctx.dr6(), 0xFFFF0FF0);
        assert_eq!(ctx.dr7(), 0x00000401);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_context_fields_do_not_overlap() {
        let mut ctx = CONTEXT::new();
        ctx.set_rip(0xAAAA_AAAA_AAAA_AAAA);
        ctx.set_rsp(0xBBBB_BBBB_BBBB_BBBB);
        ctx.set_context_flags(0xCCCCCCCC);
        ctx.set_dr(0, 0xDDDD_DDDD_DDDD_DDDD);
        // Verify none clobbered the others
        assert_eq!(ctx.rip(), 0xAAAA_AAAA_AAAA_AAAA);
        assert_eq!(ctx.rsp(), 0xBBBB_BBBB_BBBB_BBBB);
        assert_eq!(ctx.context_flags(), 0xCCCCCCCC);
        assert_eq!(ctx.dr(0), 0xDDDD_DDDD_DDDD_DDDD);
    }
}
