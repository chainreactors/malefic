// Community stub runtime.
//
// These functions match the public API of `malefic-obfuscate::runtime`.
// In community mode, proc macros expand to no-op (no encryption), so these
// are never called at runtime. They exist only to satisfy the type system.

pub fn aes_decrypt_string(
    _ciphertext: &[u8],
    _masked_key: &[u8; 32],
    _key_mask: &[u8; 32],
    _masked_iv: &[u8; 16],
    _iv_mask: &[u8; 16],
) -> String {
    unimplemented!("requires pro feature")
}

pub fn aes_decrypt_bytes(
    _ciphertext: &[u8],
    _masked_key: &[u8; 32],
    _key_mask: &[u8; 32],
    _masked_iv: &[u8; 16],
    _iv_mask: &[u8; 16],
) -> Vec<u8> {
    unimplemented!("requires pro feature")
}

pub fn xor_decrypt_bytes(_ciphertext: &[u8], _masked_key: &[u8], _key_mask: &[u8]) -> Vec<u8> {
    unimplemented!("requires pro feature")
}

pub fn aes_encrypt_field(_plaintext: &[u8], _key: &[u8; 32], _iv: &[u8; 16]) -> Vec<u8> {
    unimplemented!("requires pro feature")
}

pub fn aes_decrypt_field(_ciphertext: &[u8], _key: &[u8; 32], _iv: &[u8; 16]) -> Vec<u8> {
    unimplemented!("requires pro feature")
}

pub fn random_iv() -> [u8; 16] {
    [0u8; 16]
}

pub fn zeroize_string(_s: &mut String) {}

pub fn zeroize_vec(_v: &mut Vec<u8>) {}

pub fn zeroize_num<T: Default + Copy>(_val: &mut T) {}
