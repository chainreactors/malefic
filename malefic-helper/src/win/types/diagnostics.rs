use winapi::um::winnt::IMAGE_RUNTIME_FUNCTION_ENTRY;
// use windows::Win32::System::Diagnostics::Debug::IMAGE_RUNTIME_FUNCTION_ENTRY;

pub type RtlAddFunctionTable = unsafe extern "system" fn(
    functiontable: *const IMAGE_RUNTIME_FUNCTION_ENTRY,
    entrycount: u32,
    baseaddress: u64
) -> u8;

pub type NtFlushInstructionCache = unsafe extern "system" fn(
    hprocess: isize,
    lpbaseaddress: *const ::core::ffi::c_void,
    dwsize: usize
) -> i32;