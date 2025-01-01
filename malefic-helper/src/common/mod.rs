use std::ffi::OsString;

pub mod filesys;
pub mod memory;
pub mod sysinfo;
pub mod process;
pub mod net;
pub mod hot_modules;
pub mod loader;
pub mod utils;

pub fn format_cmdline(processname: String, params: Vec<String>) -> String {
    if params.is_empty() {
        return format_osstring(processname);
    }

    let param_str = params.join(" ");
    return format_osstring(processname + " " +  &param_str);
}
pub fn format_osstring(os_string: String) -> String {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        String::from_utf16_lossy(&OsString::from(os_string).encode_wide().collect::<Vec<u16>>())
    }
    #[cfg(not(target_os = "windows"))]
    {
        String::from(OsString::from(os_string).to_string_lossy())
    }
}

pub fn convert_u8p2vec(data: *const u8) -> Vec<u8> {
    unsafe {
        let mut ret_vec = Vec::new();
        if data.is_null()  {
            return ret_vec;
        }
        let mut i = 0;
        loop {
            let byte = *data.add(i);
            if byte == 0 {
                break;
            }
            ret_vec.push(byte);
            i += 1;
        }
        ret_vec
    }
}