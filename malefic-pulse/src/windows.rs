#![allow(non_snake_case, non_camel_case_types)]

use core::ffi::c_void;

// Windows basic types
pub type BYTE = u8;
pub type WORD = u16;
pub type DWORD = u32;
pub type LONG = i32;
pub type ULONG = u32;
pub type ULONG_PTR = usize;
pub type PVOID = *mut c_void;
pub type LPVOID = *mut c_void;
pub type HANDLE = PVOID;
pub type HMODULE = HANDLE;
pub type BOOL = i32;
pub type PSTR = *mut u8;
pub type PWSTR = *mut u16;
pub type PCH = *const i8;
pub type LPCSTR = *const i8;
pub type LPCWSTR = *const u16;
pub type UINT = u32;
pub type WCHAR = u16;
pub type NTSTATUS = i32;
pub type SIZE_T = usize;
pub type PSIZE_T = *mut SIZE_T;
pub type ACCESS_MASK = DWORD;

// Windows structures
#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}
pub type PLIST_ENTRY = *mut LIST_ENTRY;

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut WCHAR,
}
pub type PUNICODE_STRING = *mut UNICODE_STRING;

#[repr(C)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread: HANDLE,
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub Reserved1: [BYTE; 16],
    pub Reserved2: [PVOID; 10],
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
}
pub type PRTL_USER_PROCESS_PARAMETERS = *mut RTL_USER_PROCESS_PARAMETERS;

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Length: ULONG,
    pub Initialized: BOOL,
    pub SsHandle: HANDLE,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
}
pub type PPEB_LDR_DATA = *mut PEB_LDR_DATA;

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub OriginalBase: PVOID,
    pub EntryPoint: PVOID,
    pub SizeOfImage: ULONG,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub Flags: ULONG,
    pub LoadCount: u16,
    pub TlsIndex: u16,
    pub HashLinks: LIST_ENTRY,
    pub TimeDateStamp: ULONG,
}
pub type PLDR_DATA_TABLE_ENTRY = *mut LDR_DATA_TABLE_ENTRY;

#[repr(C)]
pub struct PEB {
    pub InheritedAddressSpace: BYTE,
    pub ReadImageFileExecOptions: BYTE,
    pub BeingDebugged: BYTE,
    pub BitField: BYTE,
    pub Mutant: HANDLE,
    pub ImageBaseAddress: PVOID,
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: PRTL_USER_PROCESS_PARAMETERS,
}
pub type PPEB = *mut PEB;

#[repr(C)]
pub struct TEB {
    pub Reserved1: [BYTE; 12],
    pub ProcessEnvironmentBlock: PPEB,
    pub Reserved2: [BYTE; 399],
    pub ClientId: CLIENT_ID,
}
pub type PTEB = *mut TEB;

// PE Format structures
#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: WORD,
    pub e_cblp: WORD,
    pub e_cp: WORD,
    pub e_crlc: WORD,
    pub e_cparhdr: WORD,
    pub e_minalloc: WORD,
    pub e_maxalloc: WORD,
    pub e_ss: WORD,
    pub e_sp: WORD,
    pub e_csum: WORD,
    pub e_ip: WORD,
    pub e_cs: WORD,
    pub e_lfarlc: WORD,
    pub e_ovno: WORD,
    pub e_res: [WORD; 4],
    pub e_oemid: WORD,
    pub e_oeminfo: WORD,
    pub e_res2: [WORD; 10],
    pub e_lfanew: LONG,
}
pub type PIMAGE_DOS_HEADER = *mut IMAGE_DOS_HEADER;

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: DWORD,
    pub Size: DWORD,
}
pub type PIMAGE_DATA_DIRECTORY = *mut IMAGE_DATA_DIRECTORY;

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: WORD,
    pub MajorLinkerVersion: BYTE,
    pub MinorLinkerVersion: BYTE,
    pub SizeOfCode: DWORD,
    pub SizeOfInitializedData: DWORD,
    pub SizeOfUninitializedData: DWORD,
    pub AddressOfEntryPoint: DWORD,
    pub BaseOfCode: DWORD,
    pub ImageBase: u64,
    pub SectionAlignment: DWORD,
    pub FileAlignment: DWORD,
    pub MajorOperatingSystemVersion: WORD,
    pub MinorOperatingSystemVersion: WORD,
    pub MajorImageVersion: WORD,
    pub MinorImageVersion: WORD,
    pub MajorSubsystemVersion: WORD,
    pub MinorSubsystemVersion: WORD,
    pub Win32VersionValue: DWORD,
    pub SizeOfImage: DWORD,
    pub SizeOfHeaders: DWORD,
    pub CheckSum: DWORD,
    pub Subsystem: WORD,
    pub DllCharacteristics: WORD,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: DWORD,
    pub NumberOfRvaAndSizes: DWORD,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    pub Magic: WORD,
    pub MajorLinkerVersion: BYTE,
    pub MinorLinkerVersion: BYTE,
    pub SizeOfCode: DWORD,
    pub SizeOfInitializedData: DWORD,
    pub SizeOfUninitializedData: DWORD,
    pub AddressOfEntryPoint: DWORD,
    pub BaseOfCode: DWORD,
    pub BaseOfData: DWORD,
    pub ImageBase: DWORD,
    pub SectionAlignment: DWORD,
    pub FileAlignment: DWORD,
    pub MajorOperatingSystemVersion: WORD,
    pub MinorOperatingSystemVersion: WORD,
    pub MajorImageVersion: WORD,
    pub MinorImageVersion: WORD,
    pub MajorSubsystemVersion: WORD,
    pub MinorSubsystemVersion: WORD,
    pub Win32VersionValue: DWORD,
    pub SizeOfImage: DWORD,
    pub SizeOfHeaders: DWORD,
    pub CheckSum: DWORD,
    pub Subsystem: WORD,
    pub DllCharacteristics: WORD,
    pub SizeOfStackReserve: DWORD,
    pub SizeOfStackCommit: DWORD,
    pub SizeOfHeapReserve: DWORD,
    pub SizeOfHeapCommit: DWORD,
    pub LoaderFlags: DWORD,
    pub NumberOfRvaAndSizes: DWORD,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: WORD,
    pub NumberOfSections: WORD,
    pub TimeDateStamp: DWORD,
    pub PointerToSymbolTable: DWORD,
    pub NumberOfSymbols: DWORD,
    pub SizeOfOptionalHeader: WORD,
    pub Characteristics: WORD,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct IMAGE_NT_HEADERS {
    pub Signature: DWORD,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[cfg(target_arch = "x86")]
#[repr(C)]
pub struct IMAGE_NT_HEADERS {
    pub Signature: DWORD,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER32,
}

pub type PIMAGE_NT_HEADERS = *mut IMAGE_NT_HEADERS;

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: DWORD,
    pub TimeDateStamp: DWORD,
    pub MajorVersion: WORD,
    pub MinorVersion: WORD,
    pub Name: DWORD,
    pub Base: DWORD,
    pub NumberOfFunctions: DWORD,
    pub NumberOfNames: DWORD,
    pub AddressOfFunctions: DWORD,
    pub AddressOfNames: DWORD,
    pub AddressOfNameOrdinals: DWORD,
}
pub type PIMAGE_EXPORT_DIRECTORY = *mut IMAGE_EXPORT_DIRECTORY;

// WinSock structures
#[repr(C)]
pub struct WSADATA {
    pub wVersion: WORD,
    pub wHighVersion: WORD,
    #[cfg(target_arch = "x86_64")]
    pub iMaxSockets: u16,
    #[cfg(target_arch = "x86_64")]
    pub iMaxUdpDg: u16,
    #[cfg(target_arch = "x86_64")]
    pub lpVendorInfo: *mut u8,
    pub szDescription: [u8; 257],
    pub szSystemStatus: [u8; 129],
    #[cfg(target_arch = "x86")]
    pub iMaxSockets: u16,
    #[cfg(target_arch = "x86")]
    pub iMaxUdpDg: u16,
    #[cfg(target_arch = "x86")]
    pub lpVendorInfo: *mut u8,
}

#[repr(C)]
pub struct IN_ADDR {
    pub s_addr: u32,
}

#[repr(C)]
pub struct SOCKADDR_IN {
    pub sin_family: i16,
    pub sin_port: u16,
    pub sin_addr: IN_ADDR,
    pub sin_zero: [u8; 8],
}

// OBJECT_ATTRIBUTES for NtCreateThreadEx
#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: ULONG,
    pub RootDirectory: HANDLE,
    pub ObjectName: PUNICODE_STRING,
    pub Attributes: ULONG,
    pub SecurityDescriptor: PVOID,
    pub SecurityQualityOfService: PVOID,
}

// Helper functions for accessing TEB/PEB
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn NtCurrentTeb() -> PTEB {
    let teb: PTEB;
    core::arch::asm!(
        "mov {}, gs:[0x30]",
        out(reg) teb,
        options(nostack, preserves_flags)
    );
    teb
}

#[cfg(target_arch = "x86")]
#[inline(always)]
pub unsafe fn NtCurrentTeb() -> PTEB {
    let teb: PTEB;
    core::arch::asm!(
        "mov {}, fs:[0x18]",
        out(reg) teb,
        options(nostack, preserves_flags)
    );
    teb
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn NtCurrentPeb() -> *mut PEB {
    let peb: *mut PEB;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags)
    );
    peb
}

#[cfg(target_arch = "x86")]
pub unsafe fn NtCurrentPeb() -> *mut PEB {
    let peb: *mut PEB;
    core::arch::asm!(
        "mov {}, fs:[0x30]",
        out(reg) peb,
        options(nostack, preserves_flags)
    );
    peb
}
