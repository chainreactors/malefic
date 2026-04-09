use crate::constants::{IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};
use crate::hash::{hash_string, hash_string_wide};
use crate::range_head_list;
use crate::windows::*;

pub unsafe fn module(library_hash: u32) -> usize {
    let peb = NtCurrentPeb();
    let ldr = (*peb).Ldr;
    let module_list = &(*ldr).InLoadOrderModuleList;

    let mut result = 0;

    range_head_list!(module_list, PLDR_DATA_TABLE_ENTRY, |current| {
        if library_hash == 0 {
            result = (*current).OriginalBase as usize;
            break;
        }

        if hash_string_wide((*current).BaseDllName.Buffer) == library_hash {
            result = (*current).OriginalBase as usize;
            break;
        }
    });

    result
}

pub unsafe fn _api(module_base: usize, symbol_hash: usize) -> usize {
    if module_base == 0 || symbol_hash == 0 {
        return 0;
    }

    let mut address = 0;

    let dos_header = module_base as *mut IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return 0;
    }

    let nt_headers = (module_base + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS;
    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
        return 0;
    }

    let export_dir_rva =
        (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    let export_dir = (module_base + export_dir_rva as usize) as *mut IMAGE_EXPORT_DIRECTORY;

    let names = (module_base + (*export_dir).AddressOfNames as usize) as *mut u32;
    let functions = (module_base + (*export_dir).AddressOfFunctions as usize) as *mut u32;
    let ordinals = (module_base + (*export_dir).AddressOfNameOrdinals as usize) as *mut u16;

    for i in 0..(*export_dir).NumberOfNames {
        let name_rva = *names.offset(i as isize);
        let name = (module_base + name_rva as usize) as *const u8;

        if hash_string(name) == symbol_hash as u32 {
            let ordinal = *ordinals.offset(i as isize) as isize;
            let function_rva = *functions.offset(ordinal);
            address = module_base + function_rva as usize;
            break;
        }
    }

    address
}

pub unsafe fn api<T>(module_base: usize, symbol_hash: usize) -> *mut T {
    _api(module_base, symbol_hash) as *mut T
}

#[macro_export]
macro_rules! resolve_api {
    ($module:expr, $name:ident) => {
        $crate::resolve::api::<unsafe extern "system" fn()>(
            $module,
            $crate::hash_str!(stringify!($name)) as usize,
        ) as *const unsafe extern "system" fn()
    };
}
