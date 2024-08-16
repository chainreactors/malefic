#[cfg(feature = "Mei_Asm")]
pub fn loader(shellcode : Vec<u8>) {
    // #![link_section = ".text"]
    // static buffer: [u8; 128];
    // // memcpy(buffer, shellcode.)
    // unsafe {
    //     asm!(
    //         "call {}",
    //         in(reg) buffer.as_ptr(),
    //     );
    // }
}