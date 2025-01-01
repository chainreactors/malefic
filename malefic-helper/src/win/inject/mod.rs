pub mod create_thread;

//p ub use remote_inject as create_thread::loader;

pub fn remote_inject(bin: &[u8], pid: u32) -> Result<String, String> {
    unsafe {
        create_thread::loader(bin.to_vec(), pid)
    }
}
