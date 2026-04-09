#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]
#![allow(invalid_value)]
#![feature(naked_functions)]
#![no_std]
#![no_main]

#[macro_use]
pub mod utils;

pub mod types;

pub mod loader;

#[no_mangle]
pub unsafe extern "C" fn main(
    module_base: *const core::ffi::c_void,
    entry_func: *const core::ffi::c_void,
    user_data: *const core::ffi::c_void,
    user_data_len: usize,
) {
    loader::loader(module_base, entry_func, user_data, user_data_len);
}
