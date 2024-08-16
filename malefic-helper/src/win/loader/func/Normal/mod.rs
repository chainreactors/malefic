use crate::common::func;

pub fn loader(shellcode : Vec<u8>) {
    if shellcode.is_empty() {
        return;
    }
    func::loader(shellcode);
}
