pub mod create_thread;

pub fn remote_inject(bin: &[u8], pid: u32) -> Result<String, String> {
    unsafe { create_thread::loader(bin.to_vec(), pid) }
}
