use crate::kit::binding::InlinePE;

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
    timeout: u32,
    delay: u32,
) -> Vec<u8> {
    InlinePE(
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
        timeout,
        delay,
    )
    .into_bytes()
}
