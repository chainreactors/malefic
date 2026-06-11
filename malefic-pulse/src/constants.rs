#![allow(dead_code)]

// FNV1a hash constants
pub const FNV1A_PRIME: u32 = 0x01000193;
pub const FNV1A_BASIS: u32 = 0x811c9dc5;

// Constants for shellcode
#[cfg(target_arch = "x86_64")]
pub const END_OFFSET: usize = 0x10;

#[cfg(target_arch = "x86")]
pub const END_OFFSET: usize = 0x10;

// Windows constants
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

// Memory allocation constants
pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// WinSock constants
pub const AF_INET: i32 = 2;
pub const SOCK_STREAM: i32 = 1;
pub const IPPROTO_TCP: i32 = 6;

// NTSTATUS
pub const STATUS_SUCCESS: i32 = 0;

// Thread creation flags
pub const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x00000001;
