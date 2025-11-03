#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::linux::process;
#[cfg(target_os = "windows")]
use crate::win::loader;

// use crate::common::memory::malloc_and_set_memory;
// pub fn loader(shellcode : Vec<u8>) {
//     let memory = malloc_and_set_memory(shellcode);
//     if memory.is_err() {
//         return;
//     }
//     let memory = memory.unwrap();
//
//     let f: extern "C" fn() = unsafe { std::mem::transmute(memory.get_ptr()) };
//     f();
// }

