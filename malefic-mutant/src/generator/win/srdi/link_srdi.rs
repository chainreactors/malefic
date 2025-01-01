/*
    Reference: https://github.com/postrequest/link/blob/main/src/util/shellcode.rs

*/
use crate::GenerateArch;

use super::{shellcode::{LINK_RDI_SHELLCODE_32, LINK_RDI_SHELLCODE_64}, utils::{hash_function_name, pack}};

pub fn link_shellcode_rdi_from_bytes(
    arch: &GenerateArch,
    dll_bytes: &[u8],
    function_name: &String,
    user_data: &[u8]
) -> Vec<u8> {
    let clear_header = true;
    let hash_function: [u8; 4];
    if !function_name.eq("") {
        let hash_function_u32 = hash_function_name(&function_name);
        hash_function = pack(hash_function_u32);
    } else {
        hash_function = pack(0x10_u32);
    }
    let mut flags = 0;
    if clear_header {
        flags = 0x1;
    }
    let user_data = if user_data.is_empty() {
        "None".as_bytes().to_vec()
    } else {
        user_data.to_vec()
    };
    match arch {
        GenerateArch::X64 => {
            convert_to_x86_64_shellcode(dll_bytes, hash_function, &user_data, flags)
        }
        GenerateArch::X86 => {
            convert_to_x86_shellcode(dll_bytes, hash_function, &user_data, flags)
        }
    }
}

pub fn convert_to_x86_64_shellcode(
    dll_bytes: &[u8],
    function_hash: [u8; 4],
    user_data: &[u8],
    flags: u32
) -> Vec<u8> {
    let mut final_shellcode: Vec<u8> = Vec::new();

    let bootstrap_size = 64;
    // call next intruction (Pushes next intruction address to stack)
    let mut bootstrap = Vec::new();
    bootstrap.extend_from_slice(&[0xe8, 0x00, 0x00, 0x00, 0x00]);

    // Set the offset to our DLL from pop result
    let dll_offset = bootstrap_size - bootstrap.len() + LINK_RDI_SHELLCODE_64.len();

    // pop rcx - Capture our current location in memory
    bootstrap.extend_from_slice(&[0x59]);

    // mov r8, rcx - copy our location in memory to r8 before we start modifying RCX
    bootstrap.extend_from_slice(&[0x49, 0x89, 0xc8]);

    // add rcx, <Offsett of the DLL>
    bootstrap.extend_from_slice(&[0x48, 0x81, 0xc1]);
    bootstrap.extend_from_slice(&pack(dll_offset as u32));

    // mov edx, <Hash of function>
    bootstrap.extend_from_slice(&[0xba]);
    bootstrap.extend_from_slice(&function_hash);

    // Setup the location of our user data
    // add r8, <Offset of the DLL> + <Length of DLL>
    bootstrap.extend_from_slice(&[0x49, 0x81, 0xc0]);
    let user_data_location = dll_offset + dll_bytes.len();
    bootstrap.extend_from_slice(&pack(user_data_location as u32));

    // mov r9d, <Length of User Data>
    bootstrap.extend_from_slice(&[0x41, 0xb9]);
    bootstrap.extend_from_slice(&pack(user_data.len() as u32));

    // push rsi - save original value
    bootstrap.extend_from_slice(&[0x56]);

    // mov rsi, rsp - store our current stack pointer for later
    bootstrap.extend_from_slice(&[0x48, 0x89, 0xe6]);

    // and rsp, 0x0FFFFFFFFFFFFFFF0 - Align the stack to 16 bytes
    bootstrap.extend_from_slice(&[0x48, 0x83, 0xe4, 0xf0]);

    // sub rsp, 0x30 - Create some breathing room on the stack
    bootstrap.extend_from_slice(&[0x48, 0x83, 0xec]);
    bootstrap.extend_from_slice(&[0x30]); // 32 bytes for shadow space + 8 bytes for last arg + 8 bytes for stack alignment

    // mov dword ptr [rsp + 0x20], <Flags> - Push arg 5 just above shadow space
    bootstrap.extend_from_slice(&[0xC7, 0x44, 0x24]);
    bootstrap.extend_from_slice(&[0x20]);
    bootstrap.extend_from_slice(&pack(flags as u32));

    // call - Transfer execution to the RDI
    bootstrap.extend_from_slice(&[0xe8]);
    let remainder_of_instructions = bootstrap_size - bootstrap.len() - 4;
    bootstrap.extend_from_slice(&[remainder_of_instructions as u8]); // Skip over the remainder of instructions
    bootstrap.extend_from_slice(&[0x00, 0x00, 0x00]);

    // mov rsp, rsi - Reset our original stack pointer
    bootstrap.extend_from_slice(&[0x48, 0x89, 0xf4]);

    // pop rsi - Put things back where we left them
    bootstrap.extend_from_slice(&[0x5e]);

    // ret - return to caller
    bootstrap.extend_from_slice(&[0xc3]);

    // Ends up looking like this in memory:
    // Bootstrap shellcode
    // RDI shellcode
    // DLL bytes
    // User data
    final_shellcode.extend_from_slice(&bootstrap);
    final_shellcode.extend_from_slice(&LINK_RDI_SHELLCODE_64);
    final_shellcode.extend_from_slice(&dll_bytes);
    final_shellcode.extend_from_slice(&user_data);
    final_shellcode
}

pub fn convert_to_x86_shellcode(
    dll_bytes: &[u8],
    function_hash: [u8; 4],
    user_data: &[u8],
    flags: u32
) -> Vec<u8> {
    let mut final_shellcode: Vec<u8> = Vec::new();
    let bootstrap_size = 45;

    // call next intruction (Pushes next intruction address to stack)
    let mut bootstrap = Vec::new();
    bootstrap.extend_from_slice(&[0xe8, 0x00, 0x00, 0x00, 0x00]);

    // Set the offset to our DLL from pop result
    let dll_offset = bootstrap_size - bootstrap.len() + LINK_RDI_SHELLCODE_32.len();

    // pop eax - Capture our current location in memory
    bootstrap.extend_from_slice(&[0x58]);

    // mov ebx, eax - copy our location in memory to ebx before we start modifying eax
    bootstrap.extend_from_slice(&[0x89, 0xc3]);

    // add eax, <Offset to the DLL>
    bootstrap.extend_from_slice(&[0x05]);
    bootstrap.extend_from_slice(&pack(dll_offset as u32));

    // add ebx, <Offset to the DLL> + <Size of DLL>
    bootstrap.extend_from_slice(&[0x81, 0xc3]);
    let user_data_location = dll_offset + dll_bytes.len();
    bootstrap.extend_from_slice(&pack(user_data_location as u32));

    // push <Flags>
    bootstrap.extend_from_slice(&[0x68]);
    bootstrap.extend_from_slice(&pack(flags as u32));

    // push <Length of User Data>
    bootstrap.extend_from_slice(&[0x68]);
    bootstrap.extend_from_slice(&pack(user_data.len() as u32));

    // push ebx
    bootstrap.extend_from_slice(&[0x53]);

    // push <hash of function>
    bootstrap.extend_from_slice(&[0x68]);
    bootstrap.extend_from_slice(&function_hash);

    // push eax
    bootstrap.extend_from_slice(&[0x50]);

    // call - Transfer execution to the RDI
    bootstrap.extend_from_slice(&[0xe8]);
    let remainder_of_instructions = bootstrap_size - bootstrap.len() - 4;
    bootstrap.extend_from_slice(&[remainder_of_instructions as u8]);
    bootstrap.extend_from_slice(&[0x00, 0x00, 0x00]);

    // add esp, 0x14 - correct the stack pointer
    bootstrap.extend_from_slice(&[0x83, 0xc4, 0x14]);

    // ret - return to caller
    bootstrap.extend_from_slice(&[0xc3]);

    // Ends up looking like this in memory:
    // Bootstrap shellcode
    // RDI shellcode
    // DLL bytes
    // User data
    final_shellcode.extend_from_slice(&bootstrap);
    final_shellcode.extend_from_slice(&LINK_RDI_SHELLCODE_32);
    final_shellcode.extend_from_slice(&dll_bytes);
    final_shellcode.extend_from_slice(&user_data);
    final_shellcode
}