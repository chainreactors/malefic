use core::{
    arch::asm,
    ffi::c_void,
    mem::{size_of, transmute},
    ptr::{null, read_unaligned},
};

use crate::{
    types::{
        BuildThreshold, DllMain, GetProcAddress, LdrpHandleTlsData, LoadLibraryA,
        NtFlushInstructionCache, RtlAddFunctionTable, RtlGetVersion, VerShort, VirtualAlloc,
        VirtualProtect, WinVer, BASE_RELOCATION_BLOCK, BASE_RELOCATION_ENTRY, DLL_BEACON_USER_DATA,
        IMAGE_ORDINAL, IMAGE_RUNTIME_FUNCTION_ENTRY, OSVERSIONINFOEXW, WIN32_WIN_NT_WIN10,
        WIN32_WIN_NT_WIN7, WIN32_WIN_NT_WIN8, WIN32_WIN_NT_WINBLUE, WIN32_WIN_NT_WINXP,
    },
    utils::{srdi_memcmp, IsWindows1020H1OrGreater},
};

use crate::utils::{
    boyer_moore, dbj2_str_hash, get_cstr_len, pointer_add, pointer_sub, srdi_memcpy, srdi_memset,
    IsWindows1019H1OrGreater, IsWindows10RS2OrGreater, IsWindows10RS3OrGreater,
    IsWindows10RS4OrGreater, IsWindows10RS5OrGreater, IsWindows11BetaOrGreater,
    IsWindows7OrGreater, IsWindows8OrGreater, IsWindows8Point1OrGreater,
};
use winapi::um::winnt::{
    IMAGE_BASE_RELOCATION, IMAGE_DELAYLOAD_DESCRIPTOR, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
    IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE,
    IMAGE_ORDINAL_FLAG, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
    IMAGE_SECTION_HEADER, IMAGE_THUNK_DATA, IMAGE_TLS_DIRECTORY, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows_sys::Win32::System::{
    Threading::{PEB, PEB_LDR_DATA},
    WindowsProgramming::LDR_DATA_TABLE_ENTRY,
};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub type Main = extern "system" fn();

pub unsafe fn loader(
    module_base: *const c_void,
    entry_func: *const c_void,
    user_data: *const core::ffi::c_void,
    user_data_len: usize,
) {
    let dos_headers = module_base as *mut IMAGE_DOS_HEADER;
    if (*dos_headers).e_magic.ne(&IMAGE_DOS_SIGNATURE) {
        return;
    }

    let nt_header = get_nt_header!(module_base);
    if (*nt_header).Signature.ne(&IMAGE_NT_SIGNATURE) {
        return;
    }
    let option_header = &(*nt_header).OptionalHeader;
    let file_header = &(*nt_header).FileHeader;

    let section_header = pointer_add(
        option_header as _,
        file_header.SizeOfOptionalHeader as usize,
    ) as *const IMAGE_SECTION_HEADER;

    let kernel32 = get_module_base_by_hash(0x6ddb9555);
    let ntdll = get_module_base_by_hash(0x1edab0ed);
    if kernel32.is_null() || ntdll.is_null() {
        return;
    }

    let load_library_a = get_export_by_hash(kernel32, 0xb7072fdb);
    let get_proc_address = get_export_by_hash(kernel32, 0xdecfc1bf);
    let virtual_alloc = get_export_by_hash(kernel32, 0x97bc257);
    let virtual_protect = get_export_by_hash(kernel32, 0xe857500d);
    let nt_flush_instruction_cache = get_export_by_hash(ntdll, 0x6269b87f);
    let rtl_get_version = get_export_by_hash(ntdll, 0xdde5cdd);

    if load_library_a.is_null()
        || get_proc_address.is_null()
        || virtual_alloc.is_null()
        || virtual_protect.is_null()
        || nt_flush_instruction_cache.is_null()
        || rtl_get_version.is_null()
    {
        return;
    }

    let load_library_a: LoadLibraryA = transmute(load_library_a);
    let get_proc_address: GetProcAddress = transmute(get_proc_address);
    let virtual_alloc: VirtualAlloc = transmute(virtual_alloc);
    let virtual_protect: VirtualProtect = transmute(virtual_protect);

    let nt_flush_instruction_cache: NtFlushInstructionCache = transmute(nt_flush_instruction_cache);
    let mut rebase_offset = 0;

    let mut virtual_base_address = virtual_alloc(
        option_header.ImageBase as _,
        option_header.SizeOfImage as _,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    );

    if virtual_base_address.is_null() {
        virtual_base_address = virtual_alloc(
            0 as *mut c_void,
            option_header.SizeOfImage as _,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        );
        if virtual_base_address.is_null() {
            return;
        }
        rebase_offset = virtual_base_address as usize - option_header.ImageBase as usize;
    }

    srdi_memcpy(
        virtual_base_address as _,
        module_base as _,
        option_header.SizeOfHeaders as _,
    );
    let mut section_header = section_header;

    for _ in 0..file_header.NumberOfSections {
        let mut _old_protection = 0;
        let section_addr = pointer_add(virtual_base_address, (*section_header).VirtualAddress as _);
        let section_data = pointer_add(module_base, (*section_header).PointerToRawData as _);
        srdi_memcpy(
            section_addr as _,
            section_data as _,
            (*section_header).SizeOfRawData as _,
        );

        section_header = section_header.offset(1);
    }

    let relocations = &option_header.DataDirectory[5];

    if rebase_offset.ne(&0) && relocations.Size.ne(&0) {
        let block_size = size_of::<BASE_RELOCATION_BLOCK>();
        let entry_size = size_of::<BASE_RELOCATION_ENTRY>();
        let mut reloc_block = pointer_add(virtual_base_address, relocations.VirtualAddress as _)
            as *mut IMAGE_BASE_RELOCATION;

        while (*reloc_block).VirtualAddress.ne(&0) {
            let relocation_count =
                ((*reloc_block).SizeOfBlock - block_size as u32) / entry_size as u32;
            let relocation_entry =
                pointer_add(reloc_block, block_size) as *const BASE_RELOCATION_ENTRY;

            for i in 0..relocation_count {
                let entry = relocation_entry.offset(i as _);
                if (*entry).type_().eq(&0) {
                    continue;
                }
                let rva = (*reloc_block).VirtualAddress as usize + (*entry).offset_() as usize;
                let dest = pointer_add(virtual_base_address, rva as _);
                *(dest as *mut usize) = *(dest as *mut usize) + rebase_offset as usize;
            }
            reloc_block = pointer_add(reloc_block as _, (*reloc_block).SizeOfBlock as _)
                as *mut IMAGE_BASE_RELOCATION;
        }
    }

    let imports = &option_header.DataDirectory[1];
    let mut import_descriptor_ptr =
        pointer_add(virtual_base_address, imports.VirtualAddress as usize)
            as *const IMAGE_IMPORT_DESCRIPTOR;

    while (*import_descriptor_ptr).Name.ne(&0) {
        let lib_name = pointer_add(virtual_base_address, (*import_descriptor_ptr).Name as _);
        let lib = load_library_a(lib_name as *mut i8);

        let mut ori_thunk_ptr;
        if (*import_descriptor_ptr).u.OriginalFirstThunk().ne(&0) {
            ori_thunk_ptr = pointer_add(
                virtual_base_address,
                *(*import_descriptor_ptr).u.OriginalFirstThunk() as usize,
            ) as *mut IMAGE_THUNK_DATA;
        } else {
            ori_thunk_ptr = pointer_add(
                virtual_base_address,
                (*import_descriptor_ptr).FirstThunk as _,
            ) as *mut IMAGE_THUNK_DATA;
        };

        let mut thunk_ptr = pointer_add(
            virtual_base_address,
            (*import_descriptor_ptr).FirstThunk as _,
        ) as *mut IMAGE_THUNK_DATA;

        while (*ori_thunk_ptr).u1.Function().ne(&0) {
            let ordinal = (*ori_thunk_ptr).u1.Ordinal();
            if IMAGE_SNAP_BY_ORDINAL(ordinal) {
                let ordinal = IMAGE_ORDINAL_FUNC(ordinal);
                *(*thunk_ptr).u1.Function_mut() = get_proc_address(lib, (ordinal) as *mut _) as _;
            } else {
                let name_ptr = pointer_add(
                    virtual_base_address,
                    *(*ori_thunk_ptr).u1.AddressOfData() as _,
                ) as *mut IMAGE_IMPORT_BY_NAME;
                *(*thunk_ptr).u1.Function_mut() =
                    get_proc_address(lib, &(*name_ptr).Name[0] as *const _ as *mut _) as _;
            }
            thunk_ptr = thunk_ptr.offset(1);
            ori_thunk_ptr = ori_thunk_ptr.offset(1);
        }

        import_descriptor_ptr = import_descriptor_ptr.offset(1);
    }

    let delay_import_dir = &option_header.DataDirectory[13];
    let mut delay_import_ptr =
        pointer_add(virtual_base_address, delay_import_dir.VirtualAddress as _)
            as *mut IMAGE_DELAYLOAD_DESCRIPTOR;

    if delay_import_dir.Size.gt(&0) {
        while (*delay_import_ptr).DllNameRVA.ne(&0) {
            let lib_name = pointer_add(virtual_base_address, (*delay_import_ptr).DllNameRVA as _);
            let lib = load_library_a(lib_name as _);

            let mut orig_thunk = pointer_add(
                virtual_base_address,
                (*delay_import_ptr).ImportNameTableRVA as _,
            ) as *mut IMAGE_THUNK_DATA;
            let mut thunk = pointer_add(
                virtual_base_address,
                (*delay_import_ptr).ImportAddressTableRVA as _,
            ) as *mut IMAGE_THUNK_DATA;

            while (*orig_thunk).u1.Function().ne(&0) {
                if IMAGE_SNAP_BY_ORDINAL((*orig_thunk).u1.Ordinal() as _) {
                    let func_ordinal = IMAGE_ORDINAL_FUNC((*orig_thunk).u1.Ordinal() as _);
                    *(*thunk).u1.Function_mut() = get_proc_address(lib, func_ordinal as _) as _;
                } else {
                    let func_name =
                        pointer_add(virtual_base_address, *(*orig_thunk).u1.AddressOfData() as _)
                            as *mut IMAGE_IMPORT_BY_NAME;
                    *(*thunk).u1.Function_mut() =
                        get_proc_address(lib, &(*func_name).Name[0] as *const _ as *mut _) as _;
                }

                thunk = thunk.offset(1);
                orig_thunk = orig_thunk.offset(1);
            }

            delay_import_ptr = delay_import_ptr.offset(1);
        }
    }

    let mut section_header = pointer_add(
        &(*nt_header).OptionalHeader as _,
        file_header.SizeOfOptionalHeader as _,
    ) as *const IMAGE_SECTION_HEADER;

    for _ in 0..file_header.NumberOfSections {
        let mut _old_protection = 0;
        let section_addr = pointer_add(virtual_base_address, (*section_header).VirtualAddress as _);

        let protection = match (
            ((*section_header).Characteristics & IMAGE_SCN_MEM_EXECUTE).ne(&0),
            ((*section_header).Characteristics & IMAGE_SCN_MEM_WRITE).ne(&0),
            ((*section_header).Characteristics & IMAGE_SCN_MEM_READ).ne(&0),
        ) {
            (true, true, true) => PAGE_EXECUTE_READWRITE,
            (true, true, false) => PAGE_EXECUTE_WRITECOPY,
            (true, false, true) => PAGE_EXECUTE_READ,
            (true, false, false) => PAGE_EXECUTE,
            (false, true, true) => PAGE_READWRITE,
            (false, true, false) => PAGE_WRITECOPY,
            (false, false, true) => PAGE_READONLY,
            _ => 0,
        };

        virtual_protect(
            section_addr,
            (*section_header).SizeOfRawData as _,
            protection,
            &mut _old_protection,
        );
        section_header = section_header.offset(1);
    }

    let _ = nt_flush_instruction_cache(-1 as _, null(), 0);
    let win_ver = get_win_ver(rtl_get_version);
    LdrpHandleTlsData(ntdll, virtual_base_address, &win_ver);

    let tls_data = &option_header.DataDirectory[9];
    if tls_data.Size.gt(&0) {
        let tls_dir_ptr = pointer_add(virtual_base_address, tls_data.VirtualAddress as _)
            as *mut IMAGE_TLS_DIRECTORY;
        let mut callback_ptr = (*tls_dir_ptr).AddressOfCallBacks as *const *const c_void;

        while !(*callback_ptr).is_null() {
            transmute::<*const c_void, DllMain>(*callback_ptr)(
                virtual_base_address as _,
                1,
                0 as _,
            );
            callback_ptr = callback_ptr.offset(1);
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        let rtl_add_function_table = get_export_by_hash(kernel32, 0x81a887ce);
        if rtl_add_function_table.is_null() {
            return;
        }
        let rtl_add_function_table: RtlAddFunctionTable = transmute(rtl_add_function_table);
        let exception_dir = &option_header.DataDirectory[3];
        if exception_dir.Size.gt(&0) {
            let rf_entry = pointer_add(virtual_base_address, tls_data.VirtualAddress as usize)
                as *mut IMAGE_RUNTIME_FUNCTION_ENTRY;
            let _ = rtl_add_function_table(
                rf_entry,
                (exception_dir.Size / size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>() as u32) - 1,
                virtual_base_address as _,
            );
        }
    }

    let entrypoint = pointer_add(virtual_base_address, option_header.AddressOfEntryPoint as _);
    let user_data_ptr = virtual_alloc(
        0 as _,
        user_data_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    srdi_memcpy(user_data_ptr as _, user_data as _, user_data_len);
    if entry_func.is_null() {
        // EXE maybe
        transmute::<usize, DllMain>(entrypoint as _)(0 as _, 1, 0 as _);
        return;
    }
    transmute::<usize, DllMain>(entrypoint as _)(0 as _, DLL_BEACON_USER_DATA, user_data_ptr as _);
    let entry_func = pointer_add(virtual_base_address, entry_func as _);
    transmute::<*const core::ffi::c_void, Main>(entry_func);
}

#[used]
#[no_mangle]
pub static _fltused: i32 = 0;

#[inline]
#[cfg(target_arch = "x86_64")]
fn IMAGE_SNAP_BY_ORDINAL(ordinal: &u64) -> bool {
    (ordinal & IMAGE_ORDINAL_FLAG) != 0
}

#[inline]
#[cfg(target_arch = "x86_64")]
fn IMAGE_ORDINAL_FUNC(odrinal: &u64) -> usize {
    (odrinal & (IMAGE_ORDINAL as u64)) as _
}

#[inline]
#[cfg(target_arch = "x86")]
fn IMAGE_SNAP_BY_ORDINAL(ordinal: &u32) -> bool {
    (ordinal & IMAGE_ORDINAL_FLAG) != 0
}

#[inline]
#[cfg(target_arch = "x86")]
fn IMAGE_ORDINAL_FUNC(odrinal: &u32) -> usize {
    (odrinal & (IMAGE_ORDINAL as u32)) as _
}

#[inline]
fn get_peb() -> usize {
    let ax: usize;
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            asm!(
                "mov {}, qword ptr gs:[0x60]",
                lateout(reg) ax,
                options(nostack, pure, readonly),
            );
        }
    }
    #[cfg(target_arch = "x86")]
    {
        let eax: u32;
        unsafe {
            asm!(
                "mov {}, dword ptr fs:[0x30]",
                out(reg) eax,
                options(nostack, pure, readonly),
            );
        }
        ax = eax as _;
        return ax;
    }
    ax
}

#[no_mangle]
unsafe fn memset(dst: *mut c_void, val: u8, len: usize) {
    srdi_memset(dst as _, val, len);
}

unsafe fn get_win_ver(rtl_get_version: *const core::ffi::c_void) -> WinVer {
    let mut native: OSVERSIONINFOEXW = core::mem::zeroed();
    transmute::<*const c_void, RtlGetVersion>(rtl_get_version)(&mut native as *mut _ as _);
    let fullver = native.dwMajorVersion << 8 | native.dwMinorVersion;
    let ver = match fullver {
        WIN32_WIN_NT_WIN10 => {
            if native
                .dwBuildNumber
                .ge(&(BuildThreshold::BUILD_Win11Beta as _))
            {
                VerShort::WIN11_Beta
            } else if native.dwBuildNumber.ge(&(BuildThreshold::BUILD_20_H1 as _)) {
                VerShort::WIN10_20H1
            } else if native.dwBuildNumber.ge(&(BuildThreshold::BUILD_19_H2 as _)) {
                VerShort::WIN10_19H2
            } else if native.dwBuildNumber.ge(&(BuildThreshold::BUILD_19_H1 as _)) {
                VerShort::WIN10_19H1
            } else if native.dwBuildNumber.ge(&(BuildThreshold::BUILD_RS5 as _)) {
                VerShort::WIN10_RS6
            } else if native.dwBuildNumber.ge(&(BuildThreshold::BUILD_RS4 as _)) {
                VerShort::WIN10_RS5
            } else if native.dwBuildNumber.ge(&(BuildThreshold::BUILD_RS3 as _)) {
                VerShort::WIN10_RS4
            } else if native.dwBuildNumber.ge(&(BuildThreshold::BUILD_RS2 as _)) {
                VerShort::WIN10_RS3
            } else if native.dwBuildNumber.ge(&(BuildThreshold::BUILD_RS1 as _)) {
                VerShort::WIN10_RS2
            } else if native.dwBuildNumber.ge(&(BuildThreshold::BUILD_RS0 as _)) {
                VerShort::WIN10_RS1
            } else {
                VerShort::WIN10
            }
        }
        WIN32_WIN_NT_WINBLUE => VerShort::WIN8_POINT1,
        WIN32_WIN_NT_WIN8 => VerShort::WIN8,
        WIN32_WIN_NT_WIN7 => VerShort::WIN7,
        WIN32_WIN_NT_WINXP => VerShort::WIN_XP,
        _ => VerShort::WIN_UNSUPPORTED,
    };
    WinVer {
        ver,
        rversion: native.dwBuildNumber,
        native,
    }
}

unsafe fn get_module_base_by_hash(module_hash: u32) -> *const c_void {
    let peb = get_peb() as *mut PEB;
    let peb_ldr_data_ptr = (*peb).Ldr as *mut PEB_LDR_DATA;
    let mut module_list =
        (*peb_ldr_data_ptr).InMemoryOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;
    let last_entry = (*peb_ldr_data_ptr).InMemoryOrderModuleList.Blink as *mut LDR_DATA_TABLE_ENTRY;
    let mut module = read_unaligned(module_list);

    while !module.DllBase.is_null() {
        let dll_buffer_ptr = module.FullDllName.Buffer;
        let dll_length = module.FullDllName.Length as usize;
        let dll_name_slice = core::slice::from_raw_parts(dll_buffer_ptr as *const u8, dll_length);

        if module_hash == dbj2_str_hash(dll_name_slice) {
            return module.Reserved2[0] as _;
        }
        if module_list == last_entry {
            break;
        }
        module_list = module.Reserved1[0] as *mut LDR_DATA_TABLE_ENTRY;

        module = read_unaligned(module_list);
    }

    null()
}

unsafe fn get_export_by_hash(module_base: *const c_void, func_hash: u32) -> *const c_void {
    let nt_headers = get_nt_header!(module_base);
    let export_dir = &(*nt_headers).OptionalHeader.DataDirectory[0];
    let export_dir_ptr = pointer_add(module_base, export_dir.VirtualAddress as usize)
        as *const IMAGE_EXPORT_DIRECTORY;
    if export_dir_ptr.is_null() {
        return null();
    }
    let export_dir = read_unaligned(export_dir_ptr);
    let func_rva = pointer_add(module_base, export_dir.AddressOfFunctions as usize) as *const u32;
    let func_name_rva = pointer_add(module_base, export_dir.AddressOfNames as usize) as *const u32;
    let func_ord_rva =
        pointer_add(module_base, export_dir.AddressOfNameOrdinals as usize) as *const u16;

    for i in 0..(export_dir.NumberOfFunctions as isize) {
        let func_name = pointer_add(
            module_base,
            read_unaligned(func_name_rva.offset(i)) as usize,
        ) as *const u8;
        let hsah = dbj2_str_hash(core::slice::from_raw_parts(
            func_name,
            get_cstr_len(func_name),
        ));
        if hsah.eq(&func_hash) {
            let func_ord = read_unaligned(func_ord_rva.offset(i)) as isize;
            return pointer_add(
                module_base,
                read_unaligned(func_rva.offset(func_ord)) as usize,
            ) as _;
        }
    }

    null()
}

#[no_mangle]
unsafe fn get_section_range(
    module_base: *const c_void,
    section_name: &[u8],
) -> (*const c_void, usize) {
    let dos_headers = module_base as *mut IMAGE_DOS_HEADER;
    if (*dos_headers).e_magic.ne(&IMAGE_DOS_SIGNATURE) {
        return (null(), 0);
    }

    let nt_headers = get_nt_header!(module_base);
    if (*nt_headers).Signature.ne(&IMAGE_NT_SIGNATURE) {
        return (null(), 0);
    }

    let file_header = &(*nt_headers).FileHeader;
    let option_header = &(*nt_headers).OptionalHeader;
    let mut section_header = pointer_add(
        option_header as _,
        file_header.SizeOfOptionalHeader as usize,
    ) as *const IMAGE_SECTION_HEADER;

    let section_name = core::str::from_utf8_unchecked(section_name);
    for _ in 0..file_header.NumberOfSections {
        let section = section_header;
        let name = core::str::from_utf8_unchecked(&(*section).Name);
        if name.contains(section_name) {
            let section_addr = pointer_add(module_base, (*section).VirtualAddress as usize);
            return (section_addr, *(*section).Misc.VirtualSize() as usize);
        }
        section_header = section_header.offset(1);
    }

    (null(), 0)
}

#[no_mangle]
unsafe fn LdrpHandleTlsData(ntdll: *const c_void, hmodule: *mut c_void, win_ver: &WinVer) -> i32 {
    let ldrp_handle_tls = search_ldrp_handle_tls(ntdll, win_ver);
    if ldrp_handle_tls.is_null() {
        return 0;
    }
    let mut ldr_data_table_entry: LDR_DATA_TABLE_ENTRY =
        core::mem::MaybeUninit::uninit().assume_init();
    srdi_memset(
        &mut ldr_data_table_entry as *mut _ as _,
        0,
        core::mem::size_of::<LDR_DATA_TABLE_ENTRY>(),
    );
    ldr_data_table_entry.DllBase = hmodule;
    if IsWindows8Point1OrGreater(win_ver) {
        transmute::<*const c_void, crate::types::LdrpHandleTlsDataWin8Point1OrGreater>(
            ldrp_handle_tls,
        )(&mut ldr_data_table_entry as *mut _ as _)
    } else {
        transmute::<*const c_void, crate::types::LdrpHandleTlsDataOther>(ldrp_handle_tls)(
            &mut ldr_data_table_entry as *mut _ as _,
        )
    }
    // #[cfg(target_arch = "x86_64")]
    // {
    //     transmute::<*const c_void, crate::types::LdrpHandleTlsData>(ldrp_handle_tls)(
    //         &mut ldr_data_table_entry as *mut _ as _
    //     )
    // }
    // #[cfg(target_arch = "x86")]
    // {
    //     if IsWindows8Point1OrGreater(win_ver) {
    //         transmute::<*const c_void, crate::types::LdrpHandleTlsDataWin8Point1OrGreater>(ldrp_handle_tls)(
    //             &mut ldr_data_table_entry as *mut _ as _
    //         )
    //     } else {
    //         transmute::<*const c_void, crate::types::LdrpHandleTlsDataOther>(ldrp_handle_tls)(
    //             &mut ldr_data_table_entry as *mut _ as _
    //         )
    //     }
    // }
}

#[no_mangle]
unsafe fn search_ldrp_handle_tls(module_base: *const c_void, win_ver: &WinVer) -> *const c_void {
    if module_base.is_null() {
        return null();
    }
    if IsWindows11BetaOrGreater(win_ver) {
        return find_ldrp_handle_tls_greator_win11(module_base) as _;
    }
    let handle = get_ldrp_handle_tls_offset_data(win_ver);
    if handle.offset.eq(&0) {
        return null();
    }
    let (section, size) = get_text_range(module_base);
    if section.is_null() || size.eq(&0) {
        return null();
    }
    let offset = boyer_moore(section as _, size, &handle.pattern, handle.real_len);
    if offset.eq(&-1) {
        return null();
    }
    let addr = (offset as usize + section as usize) as *const core::ffi::c_void;
    return check_real_start(pointer_sub(addr, handle.offset));
}

#[no_mangle]
unsafe fn check_real_start(call_addr: *const c_void) -> *const c_void {
    let mut real_start = call_addr as *const u8;
    loop {
        let data = read_unaligned(real_start);
        if data.ne(&0xcc) && data.ne(&0x90) {
            break;
        }
        real_start = real_start.add(1);
    }
    real_start as _
}

#[no_mangle]
pub unsafe fn find_ldrp_handle_tls_greator_win11(ntdll: *const c_void) -> usize {
    loop {
        let str_pattern: [u8; 18] = [
            0x4C, 0x64, 0x72, 0x70, 0x49, 0x6E, 0x69, 0x74, 0x69, 0x61, 0x6C, 0x69, 0x7A, 0x65,
            0x54, 0x6C, 0x73, 0x00,
        ];
        let s_addr;
        #[cfg(target_arch = "x86_64")]
        {
            s_addr = find_string_in_rdata(ntdll, &str_pattern);
        }
        #[cfg(target_arch = "x86")]
        {
            s_addr = find_string_in_text(ntdll, &str_pattern);
        }

        let xref_addr;
        #[cfg(target_arch = "x86_64")]
        {
            let start_pattern: [u8; 3] = [0x4C, 0x8D, 0x05];
            xref_addr = find_xref_in_text(ntdll, &start_pattern, 7, s_addr as usize);
            if xref_addr.eq(&0) {
                break;
            }
        }
        #[cfg(target_arch = "x86")]
        {
            let start_pattern: [u8; 1] = [0x68];
            xref_addr = find_xref_in_text_without_rva(ntdll, &start_pattern, 5, s_addr as usize);
            if xref_addr.eq(&0) {
                break;
            }
        }
        let xref_addr = xref_addr as usize + ntdll as usize;
        let call_code: [u8; 1] = [0xE8];
        let call_drp_log_internal_addr =
            boyer_moore(xref_addr as _, 0x30, &call_code, call_code.len());
        if call_drp_log_internal_addr.eq(&-1) {
            break;
        }
        let call_drp_log_internal_addr = call_drp_log_internal_addr as usize + xref_addr as usize;
        let call_ldr_allocate_tls_entry = boyer_moore(
            (call_drp_log_internal_addr + 5) as _,
            0x30,
            &call_code,
            call_code.len(),
        );
        if call_ldr_allocate_tls_entry.eq(&-1) {
            break;
        }
        let call_ldr_allocate_tls_entry =
            call_ldr_allocate_tls_entry as usize + call_drp_log_internal_addr + 5;

        let ldr_allocate_tls_entry = call_ldr_allocate_tls_entry
            .wrapping_add(calc_call_rva(call_ldr_allocate_tls_entry as _) as _);
        let black_list: [usize; 1] = [call_ldr_allocate_tls_entry];
        let call_ldr_allocate_tls_entry2 =
            find_call_rva_in_text(ntdll, ldr_allocate_tls_entry, &black_list);
        if call_ldr_allocate_tls_entry2.eq(&0) {
            break;
        }

        return find_func_start(ntdll, call_ldr_allocate_tls_entry2);
    }
    0
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
unsafe fn find_string_in_rdata(module_base: *const c_void, pattern: &[u8]) -> *const c_void {
    let rdata_pattern: [u8; 6] = [0x2E, 0x72, 0x64, 0x61, 0x74, 0x61];
    let (rdata, rdata_size) = get_section_range(module_base, &rdata_pattern);
    if rdata.is_null() || rdata_size.eq(&0) {
        return null();
    }
    let rdata = rdata as *const u8;
    let addr = boyer_moore(rdata, rdata_size, pattern, pattern.len());
    if addr.eq(&-1) {
        return null();
    }
    let addr = rdata.offset(addr) as _;
    return pointer_sub(addr, module_base as _);
}

#[cfg(target_arch = "x86")]
#[no_mangle]
unsafe fn find_string_in_text(module_base: *const c_void, pattern: &[u8]) -> *const c_void {
    let (text, text_size) = get_text_range(module_base);
    if text.is_null() || text_size.eq(&0) {
        return null();
    }
    let text = text as *const u8;
    let addr = boyer_moore(text, text_size, pattern, pattern.len());
    if addr.eq(&-1) {
        return null();
    }
    let dos_headers = module_base as *mut IMAGE_DOS_HEADER;
    if (*dos_headers).e_magic.ne(&IMAGE_DOS_SIGNATURE) {
        return null();
    }

    let nt_headers = get_nt_header!(module_base);
    if (*nt_headers).Signature.ne(&IMAGE_NT_SIGNATURE) {
        return null();
    }

    let file_header = &(*nt_headers).FileHeader;
    let option_header = &(*nt_headers).OptionalHeader;
    let addr = text.add(addr as _);
    return (addr as usize
        + (text as usize - module_base as usize - (*option_header).BaseOfCode as usize))
        as *const core::ffi::c_void;
}

unsafe fn get_text_range(module_base: *const c_void) -> (*const c_void, usize) {
    let text_pattern: [u8; 5] = [0x2E, 0x74, 0x65, 0x78, 0x74];
    get_section_range(module_base, &text_pattern)
}

unsafe fn find_func_start(module_base: *const c_void, call_addr: usize) -> usize {
    let (text, text_size) = get_text_range(module_base);
    if text.is_null() || text_size.eq(&0) {
        return 0;
    }
    let start_addr = text as *const u16;
    let end_addr = (text as usize + text_size) as *const u16;
    let mut ptr = call_addr as *const u16;
    if ptr.ge(&end_addr) {
        return 0;
    }

    loop {
        let data = core::ptr::read_unaligned(ptr);
        if data.eq(&0xCCCC) || data.eq(&0x9090) {
            let ptr = ptr as *const u8;
            let ptr = ptr.add(2);
            if read_unaligned(ptr).eq(&0xcc) || read_unaligned(ptr).eq(&0x90) {
                return ptr as usize + 1;
            }
            return ptr as usize;
        }
        ptr = ptr.sub(1);
        if ptr.le(&start_addr) {
            return 0;
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
unsafe fn find_xref_in_text(
    module_base: *const c_void,
    start_pattern: &[u8],
    op_code_len: usize,
    xref: usize,
) -> usize {
    let (text, text_size) = get_text_range(module_base);
    if text.is_null() || text_size.eq(&0) {
        return 0;
    }
    if start_pattern.len().gt(&12) {
        return 0;
    }
    let mut start_addr = text as *const u8;
    let mut size = text_size;
    let xref_addr = module_base as usize + xref;
    let mut new_pattern: [u8; 16] = core::mem::MaybeUninit::uninit().assume_init();
    srdi_memset(&mut new_pattern as *mut _ as _, 0, 16);
    srdi_memcpy(
        new_pattern.as_mut_ptr() as _,
        start_pattern.as_ptr() as _,
        start_pattern.len(),
    );
    let xref_op = pointer_add(new_pattern.as_ptr() as _, start_pattern.len());
    let left_len = 16 - start_pattern.len();
    loop {
        let offset = boyer_moore(start_addr, size, &start_pattern, start_pattern.len());
        if offset.eq(&-1) {
            return 0;
        }
        let rv_offset = (xref_addr - (start_addr as usize + offset as usize) - op_code_len) as i32;
        let rv_offset_bytes = rv_offset.to_le_bytes();
        srdi_memset(xref_op as _, 0, left_len);
        srdi_memcpy(
            xref_op as _,
            rv_offset_bytes.as_ptr() as _,
            rv_offset_bytes.len(),
        );
        let new_len = start_pattern.len() + rv_offset_bytes.len();
        let new_offset = boyer_moore(
            start_addr.offset(offset),
            new_pattern.len(),
            &new_pattern,
            new_len,
        );
        if new_offset.eq(&-1) {
            let offset = offset as usize + op_code_len;
            start_addr = start_addr.add(offset);
            if start_addr.gt(&(text as *const u8).add(text_size)) {
                return 0;
            } else if size.le(&offset) {
                return 0;
            }
            size = size - offset;
            continue;
        }
        return start_addr.offset(offset) as usize - module_base as usize;
    }
}

#[cfg(target_arch = "x86")]
#[no_mangle]
unsafe fn find_xref_in_text_without_rva(
    module_base: *const c_void,
    start_pattern: &[u8],
    op_code_len: usize,
    xref: usize,
) -> usize {
    let (text, text_size) = get_text_range(module_base);
    if text.is_null() || text_size.eq(&0) {
        return 0;
    }
    if start_pattern.len().gt(&12) {
        return 0;
    }
    let mut new_pattern: [u8; 16] = core::mem::MaybeUninit::uninit().assume_init();
    srdi_memset(&mut new_pattern as *mut _ as _, 0, 16);
    srdi_memcpy(
        new_pattern.as_mut_ptr() as _,
        start_pattern.as_ptr() as _,
        start_pattern.len(),
    );
    let xref = (xref as i32).to_le_bytes();
    srdi_memcpy(
        new_pattern.as_mut_ptr().add(start_pattern.len()) as _,
        xref.as_ptr() as _,
        xref.len(),
    );
    let offset = boyer_moore(text as _, text_size, &new_pattern, op_code_len);
    if offset.eq(&-1) {
        return 0;
    }
    return text.offset(offset) as usize - module_base as usize;
}

#[no_mangle]
unsafe fn find_call_rva_in_text(
    module_base: *const c_void,
    func_addr: usize,
    black_list: &[usize],
) -> usize {
    let (text, text_size) = get_text_range(module_base);
    if text.is_null() || text_size.eq(&0) {
        return 0;
    }

    let mut start_addr = text as *const u8;
    let mut size = text_size;
    let call_patt = [0xE8];
    loop {
        // let offset = boyer_moore(start_addr, size, call_patt.as_ptr(), call_patt.len());
        let offset = boyer_moore(start_addr, size, &call_patt, call_patt.len());
        if offset.eq(&-1) {
            return 0;
        }
        let call_addr = start_addr as isize + offset;
        let rva = (func_addr as isize - call_addr as isize) as i32;
        let current_rva = calc_call_rva(start_addr as usize + offset as usize);
        if current_rva.eq(&rva) && !black_list.contains(&(call_addr as usize)) {
            return start_addr as usize + offset as usize;
        }
        let offset = offset + 1;
        start_addr = start_addr.offset(offset);
        if start_addr.gt(&(text as *const u8).add(text_size)) {
            return 0;
        } else if size.le(&(offset as _)) {
            return 0;
        }
        size = size - offset as usize;
        continue;
    }
}

unsafe fn calc_call_rva(start_addr: usize) -> i32 {
    let addr = (start_addr + 1) as *const i32;
    let call_addr = core::ptr::read_unaligned(addr);
    return call_addr + 5;
}

#[no_mangle]
extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, size: usize) -> *mut c_void {
    unsafe {
        srdi_memcpy(dest as _, src as _, size);
    }
    dest
}

#[no_mangle]
extern "C" fn memcmp(dest: *const c_void, src: *const c_void, size: usize) -> i32 {
    unsafe { srdi_memcmp(dest as _, src as _, size) }
}

#[no_mangle]
pub extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if src < dest as *const u8 {
        for i in (0..n).rev() {
            unsafe {
                *dest.add(i) = *src.add(i);
            }
        }
    } else {
        for i in 0..n {
            unsafe {
                *dest.add(i) = *src.add(i);
            }
        }
    }
    dest
}

#[no_mangle]
#[cfg(target_arch = "x86_64")]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 {
    unimplemented!()
}

#[no_mangle]
#[cfg(target_arch = "x86")]
#[no_mangle]
unsafe extern "C" fn __CxxFrameHandler3() {
    unreachable!()
}

#[repr(C)]
struct ldrp_handle_tls_search {
    pattern: [u8; 0x10],
    real_len: usize,
    offset: usize,
}

unsafe fn get_ldrp_handle_tls_offset_data(win_ver: &WinVer) -> ldrp_handle_tls_search {
    let mut ret_pattern: ldrp_handle_tls_search = core::mem::zeroed();
    #[cfg(target_arch = "x86_64")]
    {
        if IsWindows10RS3OrGreater(win_ver) {
            let mut offset = 0x43;
            if IsWindows1019H1OrGreater(win_ver) {
                offset = 0x46;
            } else if IsWindows10RS4OrGreater(win_ver) {
                offset = 0x44;
            }
            let pattern = [0x74, 0x33, 0x44, 0x8D, 0x43, 0x09];
            srdi_memcpy(
                ret_pattern.pattern.as_mut_ptr(),
                pattern.as_ptr(),
                pattern.len(),
            );
            ret_pattern.offset = offset;
            ret_pattern.real_len = pattern.len();
            // return (b"\x74\x33\x44\x8d\x43\x09", offset);
        } else if IsWindows10RS2OrGreater(win_ver) {
            let pattern = [0x74, 0x33, 0x44, 0x8D, 0x43, 0x09];
            srdi_memcpy(
                ret_pattern.pattern.as_mut_ptr(),
                pattern.as_ptr(),
                pattern.len(),
            );
            ret_pattern.real_len = pattern.len();
            ret_pattern.offset = 0x43;
        } else if IsWindows8Point1OrGreater(win_ver) {
            let pattern = [0x44, 0x8D, 0x43, 0x09, 0x4C, 0x8D, 0x4C, 0x24, 0x38];
            srdi_memcpy(
                ret_pattern.pattern.as_mut_ptr(),
                pattern.as_ptr(),
                pattern.len(),
            );
            ret_pattern.real_len = pattern.len();
            ret_pattern.offset = 0x43;
            // return (b"\x44\x8d\x43\x09\x4c\x8d\x4c\x24\x38", 0x43);
        } else if IsWindows8OrGreater(win_ver) {
            let pattern = [0x48, 0x8B, 0x79, 0x30, 0x45, 0x8D, 0x66, 0x01];
            srdi_memcpy(
                ret_pattern.pattern.as_mut_ptr(),
                pattern.as_ptr(),
                pattern.len(),
            );
            ret_pattern.real_len = pattern.len();
            ret_pattern.offset = 0x49;
            // return (b"\x48\x8b\x79\x30\x45\x8d\x66\x01", 0x49);
        } else if IsWindows7OrGreater(win_ver) {
            let pattern = [
                0x41, 0xB8, 0x09, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x44, 0x24, 0x38,
            ];
            srdi_memcpy(
                ret_pattern.pattern.as_mut_ptr(),
                pattern.as_ptr(),
                pattern.len(),
            );
            ret_pattern.real_len = pattern.len();
            ret_pattern.offset = 0x27;
        }
    }
    #[cfg(target_arch = "x86")]
    {
        if IsWindows10RS3OrGreater(win_ver) {
            let pattern = [0x8b, 0xc1, 0x8d, 0x4d, 0x08, 0x51];
            srdi_memcpy(
                ret_pattern.pattern.as_mut_ptr(),
                pattern.as_ptr(),
                pattern.len(),
            );
            ret_pattern.real_len = pattern.len();
            // let mut pattern = b"\x8b\xc1\x8d\x4d\xbc\x51";
            if IsWindows10RS5OrGreater(win_ver) {
                let pattern = [0x33, 0xf6, 0x85, 0xc0, 0x79, 0x03];
                srdi_memcpy(
                    ret_pattern.pattern.as_mut_ptr(),
                    pattern.as_ptr(),
                    pattern.len(),
                );
                ret_pattern.real_len = pattern.len();
                // pattern = b"\x33\xf6\x85\xc0\x79\x03";
            } else if IsWindows10RS4OrGreater(win_ver) {
                let pattern = [0x8b, 0xc1, 0x8d, 0x4d, 0xac, 0x51];
                srdi_memcpy(
                    ret_pattern.pattern.as_mut_ptr(),
                    pattern.as_ptr(),
                    pattern.len(),
                );
                ret_pattern.real_len = pattern.len();
                // pattern = b"\x8b\xc1\x8d\x4d\xac\x51";
            }
            // let mut offset = 0x18;
            ret_pattern.offset = 0x18;
            if IsWindows1020H1OrGreater(win_ver) {
                ret_pattern.offset = 0x2c;
                // offset = 0x2C;
            } else if IsWindows1019H1OrGreater(win_ver) {
                ret_pattern.offset = 0x2e;
                // offset = 0x2E;
            } else if IsWindows10RS5OrGreater(win_ver) {
                ret_pattern.offset = 0x2c;
                // offset = 0x2C;
            }
            // return (pattern, offset);
        } else if IsWindows10RS2OrGreater(win_ver) {
            let pattern = [0x8b, 0xc1, 0x8d, 0x4d, 0xbc, 0x51];
            srdi_memcpy(
                ret_pattern.pattern.as_mut_ptr(),
                pattern.as_ptr(),
                pattern.len(),
            );
            ret_pattern.real_len = pattern.len();
            ret_pattern.offset = 0x18;
            // return (b"\x8b\xc1\x8d\x4d\xbc\x51", 0x18);
        } else if IsWindows8Point1OrGreater(win_ver) {
            let pattern = [0x50, 0x6a, 0x09, 0x6a, 0x01, 0x8b, 0xc1];
            srdi_memcpy(
                ret_pattern.pattern.as_mut_ptr(),
                pattern.as_ptr(),
                pattern.len(),
            );
            ret_pattern.real_len = pattern.len();
            ret_pattern.offset = 0x1B;
            // return (b"\x50\x6a\x09\x6a\x01\x8b\xc1", 0x1B);
        } else if IsWindows8OrGreater(win_ver) {
            let pattern = [0x8b, 0x45, 0x08, 0x89, 0x45, 0xa0];
            srdi_memcpy(
                ret_pattern.pattern.as_mut_ptr(),
                pattern.as_ptr(),
                pattern.len(),
            );
            ret_pattern.real_len = pattern.len();
            ret_pattern.offset = 0xC;
            // return (b"\x8b\x45\x08\x89\x45\xa0", 0xC);
        } else if IsWindows7OrGreater(win_ver) {
            let pattern = [0x74, 0x20, 0x8d, 0x45, 0xd4, 0x50, 0x6a, 0x09];
            srdi_memcpy(
                ret_pattern.pattern.as_mut_ptr(),
                pattern.as_ptr(),
                pattern.len(),
            );
            ret_pattern.real_len = pattern.len();
            ret_pattern.offset = 0x14;
            // return (b"\x74\x20\x8d\x45\xd4\x50\x6a\x09", 0x14);
        }
    }
    return ret_pattern;
}
