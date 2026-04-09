// use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_RUNTIME_FUNCTION_ENTRY;

pub type DllMain =
    unsafe extern "system" fn(*mut core::ffi::c_void, u32, *mut core::ffi::c_void) -> i32;
pub const IMAGE_ORDINAL: usize = 0xffff;
pub const DLL_BEACON_USER_DATA: u32 = 0x0du32;

#[repr(C)]
pub struct BASE_RELOCATION_BLOCK {
    pub PageAddress: u32,
    pub BlockSize: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct BASE_RELOCATION_ENTRY {
    offset_type: u16,
}

impl BASE_RELOCATION_ENTRY {
    pub fn offset_(&self) -> u16 {
        self.offset_type & 0xFFF
    }

    pub fn type_(&self) -> u16 {
        (self.offset_type >> 12) & 0xF
    }
}

pub type PBASE_RELOCATION_ENTRY = *mut BASE_RELOCATION_ENTRY;

#[repr(C)]
pub struct IMAGE_RUNTIME_FUNCTION_ENTRY_u([u32; 1]);
impl Copy for IMAGE_RUNTIME_FUNCTION_ENTRY_u {}
impl Clone for IMAGE_RUNTIME_FUNCTION_ENTRY_u {
    #[inline]
    fn clone(&self) -> IMAGE_RUNTIME_FUNCTION_ENTRY_u {
        *self
    }
}
impl IMAGE_RUNTIME_FUNCTION_ENTRY_u {
    pub unsafe fn UnwindInfoAddress(&self) -> &u32 {
        &*(self as *const _ as *const u32)
    }

    pub unsafe fn UnwindInfoAddress_mut(&mut self) -> &mut u32 {
        &mut *(self as *mut _ as *mut u32)
    }

    pub unsafe fn UnwindData(&self) -> &u32 {
        &*(self as *const _ as *const u32)
    }

    pub unsafe fn UnwindData_mut(&mut self) -> &mut u32 {
        &mut *(self as *mut _ as *mut u32)
    }
}

pub type RTL_OSVERSIONINFOEXW = OSVERSIONINFOEXW;

STRUCT! {
    struct OSVERSIONINFOEXW {
        dwOSVersionInfoSize: u32,
        dwMajorVersion: u32,
        dwMinorVersion: u32,
        dwBuildNumber: u32,
        dwPlatformId: u32,
        szCSDVersion: [u16; 128],
        wServicePackMajor: u16,
        wServicePackMinor: u16,
        wSuiteMask: u16,
        wProductType: u8,
        wReserved: u8,
    }
}

#[repr(C)]
pub struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    pub BeginAddress: u32,
    pub EndAddress: u32,
    pub u: IMAGE_RUNTIME_FUNCTION_ENTRY_u,
}

pub type IMAGE_RUNTIME_FUNCTION_ENTRY = _IMAGE_RUNTIME_FUNCTION_ENTRY;
pub type PRUNTIME_FUNCTION = *const IMAGE_RUNTIME_FUNCTION_ENTRY;

pub type VirtualAlloc = unsafe extern "system" fn(
    lpaddress: *const ::core::ffi::c_void,
    dwsize: usize,
    flallocationtype: u32,
    flprotect: u32,
) -> *mut ::core::ffi::c_void;

pub type LoadLibraryA =
    unsafe extern "system" fn(lplibfilename: *const i8) -> *mut ::core::ffi::c_void;

pub type GetProcAddress = unsafe extern "system" fn(
    hmodule: *mut ::core::ffi::c_void,
    lpprocname: *const i8,
) -> *mut ::core::ffi::c_void;

pub type RtlAddFunctionTable = unsafe extern "system" fn(
    functiontable: *const IMAGE_RUNTIME_FUNCTION_ENTRY,
    entrycount: u32,
    baseaddress: u64,
) -> u8;

pub type NtFlushInstructionCache = unsafe extern "system" fn(
    hprocess: isize,
    lpbaseaddress: *const ::core::ffi::c_void,
    dwsize: usize,
) -> i32;

pub type VirtualProtect = unsafe extern "system" fn(
    lpaddress: *const ::core::ffi::c_void,
    dwsize: usize,
    flnewprotect: u32,
    lpfloldprotect: *mut u32,
) -> i32;

pub type LdrpHandleTlsData = unsafe extern "system" fn(hmodule: *mut ::core::ffi::c_void) -> i32;

pub type LdrpHandleTlsDataWin8Point1OrGreater =
    unsafe extern "thiscall" fn(hmodule: *mut ::core::ffi::c_void) -> i32;

pub type LdrpHandleTlsDataOther =
    unsafe extern "stdcall" fn(hmodule: *mut ::core::ffi::c_void) -> i32;

pub type RtlGetVersion =
    unsafe extern "system" fn(lpversioninformation: *mut OSVERSIONINFOEXW) -> i32;

ENUM! {
    enum Win32WinNt {
        WIN32_WIN_NT_NT4 = 0x0400,
        WIN32_WIN_NT_WIN2_K = 0x0500,
        WIN32_WIN_NT_WINXP = 0x0501,
        WIN32_WIN_NT_WS03 = 0x0502,
        WIN32_WIN_NT_WIN6 = 0x0600,
        WIN32_WIN_NT_VISTA = 0x0600,
        WIN32_WIN_NT_WS08 = 0x0600,
        WIN32_WIN_NT_LONGHORN = 0x0600,
        WIN32_WIN_NT_WIN7 = 0x0601,
        WIN32_WIN_NT_WIN8 = 0x0602,
        WIN32_WIN_NT_WINBLUE = 0x0603,
        WIN32_WIN_NT_WIN10 = 0x0A00,
    }
}

pub enum BuildThreshold {
    BUILD_RS0 = 10586,
    BUILD_RS1 = 14393,
    BUILD_RS2 = 15063,
    BUILD_RS3 = 16299,
    BUILD_RS4 = 17134,
    BUILD_RS5 = 17763,
    BUILD_19_H1 = 18362,
    BUILD_19_H2 = 18363,
    BUILD_20_H1 = 19041,
    BUILD_Win11Beta = 21996,
    BUILD_RS_MAX = 99999,
}

pub enum VerShort {
    WIN_UNSUPPORTED, // Unsupported OS
    WIN_XP,          // Windows XP
    WIN7,            // Windows 7
    WIN8,            // Windows 8
    WIN8_POINT1,     // Windows 8.1
    WIN10,           // Windows 10
    WIN10_RS1,       // Windows 10 Anniversary update
    WIN10_RS2,       // Windows 10 Creators update
    WIN10_RS3,       // Windows 10 Fall Creators update
    WIN10_RS4,       // Windows 10 Spring Creators update
    WIN10_RS5,       // Windows 10 October 2018 update
    WIN10_RS6,       // Windows 10 May 2019 update
    WIN10_19H1,      // Windows 10 May 2019 update
    WIN10_19H2,      // Windows 10 November 2019 update
    WIN10_20H1,      // Windows 10 April 2020 update
    WIN11_Beta,      // Windows 11 Beta
}

impl From<u32> for VerShort {
    fn from(ver: u32) -> Self {
        match ver {
            0 => VerShort::WIN_UNSUPPORTED,
            1 => VerShort::WIN_XP,
            2 => VerShort::WIN7,
            3 => VerShort::WIN8,
            4 => VerShort::WIN8_POINT1,
            5 => VerShort::WIN10,
            6 => VerShort::WIN10_RS1,
            7 => VerShort::WIN10_RS2,
            8 => VerShort::WIN10_RS3,
            9 => VerShort::WIN10_RS4,
            10 => VerShort::WIN10_RS5,
            11 => VerShort::WIN10_RS6,
            12 => VerShort::WIN10_19H1,
            13 => VerShort::WIN10_19H2,
            14 => VerShort::WIN10_20H1,
            15 => VerShort::WIN11_Beta,
            _ => VerShort::WIN_UNSUPPORTED,
        }
    }
}

pub struct WinVer {
    pub ver: VerShort,
    pub rversion: u32,
    pub native: OSVERSIONINFOEXW,
}
