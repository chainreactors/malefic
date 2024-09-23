pub unsafe fn bof_loader(buffer: &Vec<u8>, arguments: &Vec<String>, entrypoint_name: Option<String>) -> String {
    #[cfg(feature = "prebuild")]
    {
        use super::MaleficBofLoader;
        use std::ffi::CString;
        let c_strings: Vec<_> = arguments.iter()
                .map(|s| {
                    let c_str = std::ffi::CString::new(s.as_str()).unwrap();
                    c_str.into_raw()
                })
                .collect();
        let entrypoint_name = match entrypoint_name {
            Some(entrypoint_name) => {
                let c_str = std::ffi::CString::new(entrypoint_name.as_str()).unwrap();
                c_str.into_raw()
            },
            None => std::ptr::null_mut()
        };
        return CString::from_raw(
            MaleficBofLoader(
                    buffer.as_ptr(), 
                    buffer.len(), 
                    c_strings.as_ptr() as _, c_strings.len(),
                    entrypoint_name as _
                ) as _
            ).to_str().unwrap_or_default().to_string();
    }
    #[cfg(feature = "source")]
    {
        use malefic_win_kit::bof::loader::bof_loader;
        match bof_loader(buffer, arguments.clone(), entrypoint_name) {
            Ok(ret) => {
                ret
            },
            Err(e) => {
                e.to_string()
            }
        }
    }
}