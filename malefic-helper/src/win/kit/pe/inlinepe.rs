
pub unsafe fn inline_pe(
    bin: *const u8,
    bin_size: usize,
    magic: *const u16,
    signature: *const u32,
    commandline: *const u8,
    commandline_len: usize,
    entrypoint: *const u8,
    entrypoint_len: usize,
    is_dll: bool,
    is_need_output: bool,
    timeout: u32
) -> Vec<u8> {
    #[cfg(feature = "prebuild")]
    {
        let ret = crate::win::kit::InlinePE(
            bin,
            bin_size,
            magic,
            signature,
            commandline,
            commandline_len,
            entrypoint,
            entrypoint_len,
            is_dll,
            is_need_output,
            timeout
        );
        let str = String::from_raw_parts(ret.data, ret.len, ret.capacity);
        str.as_bytes().to_vec()
    }
    #[cfg(feature = "source")]
    {
        use malefic_win_kit::pe::InlinePEPatched::InlinePe;
        InlinePe(
            bin,
            bin_size,
            magic,
            signature,
            commandline,
            commandline_len,
            entrypoint,
            entrypoint_len,
            is_dll,
            is_need_output,
            timeout
        )
    }
}