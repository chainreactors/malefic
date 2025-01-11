#![allow(non_camel_case_types)]
use std::os::raw::{c_int, c_uint, c_void};

pub const PROC_PIDLISTFDS: c_int = 1;
pub const PROC_PIDTASKALLINFO: c_int = 2;
pub const PROC_PIDFDSOCKETINFO: c_int = 3;

extern "C" {
    pub fn proc_listpids(
        proc_type: c_uint,
        typeinfo: c_uint,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;

    pub fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;

    pub fn proc_pidfdinfo(
        pid: c_int,
        fd: c_int,
        flavor: c_int,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
}
