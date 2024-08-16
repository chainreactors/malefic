
#[cfg(target_os = "linux")]
pub fn loader(shellcode : Vec<u8>) {
    if shellcode.is_empty() {
        return;
    }
    crate::loader::common::func::loader(shellcode);
}