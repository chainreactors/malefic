#![allow(non_camel_case_types)]
#![allow(improper_ctypes)]
extern crate libc;

pub use api::*;
pub use itab::*;
pub use types::*;

mod api;
mod itab;
mod types;

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use std::mem;
    use super::*;

    #[test]
    fn it_works() {
        let data = [
            // mov eax, [edx + esi*4]
            0x8B, 0x04, 0xB2,
            // nop
            0x90,
        ];

        unsafe {
            let mut object = mem::zeroed();
            ud_init(&mut object);
            ud_set_input_buffer(&mut object, data.as_ptr(), data.len());
            ud_set_mode(&mut object, 32);
            ud_set_syntax(&mut object, Some(ud_translate_intel));

            assert_eq!(ud_disassemble(&mut object), 3);

            let operand = ud_insn_opr(&object, 0).as_ref().unwrap();
            assert_eq!(operand.otype, ud_type::UD_OP_REG);
            assert_eq!(operand.base, ud_type::UD_R_EAX);

            let operand = ud_insn_opr(&object, 1).as_ref().unwrap();
            assert_eq!(operand.otype, ud_type::UD_OP_MEM);
            assert_eq!(operand.base, ud_type::UD_R_EDX);
            assert_eq!(operand.index, ud_type::UD_R_ESI);
            assert_eq!(operand.scale, 4);

            assert_eq!(ud_disassemble(&mut object), 1);
            let instruction = ud_insn_asm(&mut object);
            assert_eq!(CStr::from_ptr(instruction).to_string_lossy(), "nop");
        }
    }
}
