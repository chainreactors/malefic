use byteorder::{ByteOrder, LittleEndian};

pub fn pack(val: u32) -> [u8; 4] {
    let mut bytes = [0; 4];
    LittleEndian::write_u32(&mut bytes, val);
    bytes
}

pub fn ror(val: u32, r_bits: u32, max_bits: u32) -> u32 {
    let base: u64 = 2;
    let exp = base.pow(max_bits) - 1;
    ((val & exp as u32) >> r_bits.rem_euclid(max_bits))
        | (val << (max_bits - (r_bits.rem_euclid(max_bits))) & exp as u32)
}

pub fn hash_function_name(name: &str) -> u32 {
    let mut function: Vec<u8> = name.as_bytes().to_vec();
    function.extend_from_slice(&[0x00]);
    let mut function_hash: u32 = 0;

    for byte in function.iter() {
        function_hash = ror(function_hash, 13, 32);
        function_hash += *byte as u32;
    }
    function_hash
}
