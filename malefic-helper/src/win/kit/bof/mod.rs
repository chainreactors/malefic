pub unsafe fn bof_loader(buffer: &Vec<u8>, arguments: &Vec<String>, entrypoint_name: Option<String>) -> String {
    #[cfg(feature = "prebuild")]
    {
        use super::MaleficBofLoader;
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
        let ret = MaleficBofLoader(
            buffer.as_ptr(), 
            buffer.len(), 
            c_strings.as_ptr() as _, c_strings.len(),
            entrypoint_name as _
        );
        String::from_raw_parts(ret.data, ret.len, ret.capacity)
    }
    #[cfg(feature = "source")]
    {
        use malefic_win_kit::bof::loader::bof_loader_with_result;
        bof_loader_with_result(buffer, arguments.clone(), entrypoint_name)
    }
}