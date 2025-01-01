use std::ptr::{null, read_unaligned};

use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};
use crate::common::utils::{dbj2_str_hash, get_cstr_len, pointer_add};

#[cfg(target_pointer_width = "64")]
#[allow(non_camel_case_types)]
pub type IMAGE_NT_HEADERS = windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
#[cfg(target_pointer_width = "32")]
#[allow(non_camel_case_types)]
pub type IMAGE_NT_HEADERS = windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;

#[macro_export]
macro_rules! get_nt_header {
    ($base_addr: expr) => {
        {
            let dos_header = $base_addr as *mut IMAGE_DOS_HEADER;
            pointer_add($base_addr, (*dos_header).e_lfanew as _)
        }
    };
}

pub unsafe fn get_export_by_hash(
    module_base: *const core::ffi::c_void, 
    func_hash: u32,
) -> *const core::ffi::c_void {
    let nt_headers = get_nt_header!(module_base) as *const IMAGE_NT_HEADERS;
    let export_dir = &(*nt_headers).OptionalHeader.DataDirectory[0];
    let export_dir_ptr = pointer_add(
        module_base, 
        export_dir.VirtualAddress as usize
    ) as *const IMAGE_EXPORT_DIRECTORY;
    if export_dir_ptr.is_null() {
        return null();
    }
    let export_dir = read_unaligned(export_dir_ptr);
    let func_rva = pointer_add(
        module_base, 
        export_dir.AddressOfFunctions as usize
    ) as *const u32;
    let func_name_rva = pointer_add(
        module_base, 
        export_dir.AddressOfNames as usize
    ) as *const u32;
    let func_ord_rva = pointer_add(
        module_base, 
        export_dir.AddressOfNameOrdinals as usize
    ) as *const u16;

    for i in 0..(export_dir.NumberOfFunctions as isize) {
        let func_name = pointer_add(
            module_base, 
            read_unaligned(func_name_rva.offset(i)) as usize
        ) as *const u8;
        let hsah = dbj2_str_hash(core::slice::from_raw_parts(
            func_name, get_cstr_len(func_name)));
        if hsah.eq(&func_hash) {
            let func_ord = read_unaligned(func_ord_rva.offset(i)) as isize;
            return pointer_add(
                module_base, 
                read_unaligned(func_rva.offset(func_ord)) as usize
            ) as _;
        }
    }

    null()
}