//! Base64 codec

#[cfg(feature = "encoder")]
use crate::EncodeResult;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const DECODE_TABLE: [u8; 128] = {
    let mut table = [0xFFu8; 128];
    let mut i = 0;
    while i < 64 {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

#[cfg(feature = "encoder")]
pub fn encode(data: &[u8]) -> EncodeResult {
    let mut encoded = String::new();
    let mut i = 0;

    while i + 2 < data.len() {
        let triple = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        encoded.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        encoded.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        encoded.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        encoded.push(ALPHABET[(triple & 0x3F) as usize] as char);
        i += 3;
    }

    let remaining = data.len() - i;
    if remaining == 1 {
        let triple = (data[i] as u32) << 16;
        encoded.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        encoded.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        encoded.push('=');
        encoded.push('=');
    } else if remaining == 2 {
        let triple = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        encoded.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        encoded.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        encoded.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        encoded.push('=');
    }

    EncodeResult {
        encoded: encoded.as_bytes().to_vec(),
        key: vec![],
        extra: vec![],
        strings: vec![encoded],
    }
}

pub fn decode(data: &[u8], _key: &[u8], _extra: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(data);
    let input: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    let mut result = Vec::with_capacity(input.len() * 3 / 4);

    let mut i = 0;
    while i + 3 < input.len() {
        let a = DECODE_TABLE[input[i] as usize] as u32;
        let b = DECODE_TABLE[input[i + 1] as usize] as u32;
        let c = DECODE_TABLE[input[i + 2] as usize] as u32;
        let d = DECODE_TABLE[input[i + 3] as usize] as u32;
        let triple = (a << 18) | (b << 12) | (c << 6) | d;
        result.push((triple >> 16) as u8);
        result.push((triple >> 8) as u8);
        result.push(triple as u8);
        i += 4;
    }

    let remaining = input.len() - i;
    if remaining == 2 {
        let a = DECODE_TABLE[input[i] as usize] as u32;
        let b = DECODE_TABLE[input[i + 1] as usize] as u32;
        let triple = (a << 18) | (b << 12);
        result.push((triple >> 16) as u8);
    } else if remaining == 3 {
        let a = DECODE_TABLE[input[i] as usize] as u32;
        let b = DECODE_TABLE[input[i + 1] as usize] as u32;
        let c = DECODE_TABLE[input[i + 2] as usize] as u32;
        let triple = (a << 18) | (b << 12) | (c << 6);
        result.push((triple >> 16) as u8);
        result.push((triple >> 8) as u8);
    }

    result
}
