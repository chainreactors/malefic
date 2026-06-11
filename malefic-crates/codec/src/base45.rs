//! Base45 codec

#[cfg(feature = "encoder")]
use crate::EncodeResult;

const BASE45_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

fn char_to_val(c: u8) -> Option<u32> {
    BASE45_ALPHABET
        .iter()
        .position(|&b| b == c)
        .map(|p| p as u32)
}

#[cfg(feature = "encoder")]
pub fn encode(data: &[u8]) -> EncodeResult {
    let mut encoded = String::new();

    let mut i = 0;
    while i < data.len() {
        if i + 1 < data.len() {
            let val = (data[i] as u32) * 256 + (data[i + 1] as u32);
            let c = val / (45 * 45);
            let remainder = val % (45 * 45);
            let b = remainder / 45;
            let a = remainder % 45;
            encoded.push(BASE45_ALPHABET[a as usize] as char);
            encoded.push(BASE45_ALPHABET[b as usize] as char);
            encoded.push(BASE45_ALPHABET[c as usize] as char);
            i += 2;
        } else {
            let val = data[i] as u32;
            let b = val / 45;
            let a = val % 45;
            encoded.push(BASE45_ALPHABET[a as usize] as char);
            encoded.push(BASE45_ALPHABET[b as usize] as char);
            i += 1;
        }
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
    let input: Vec<u8> = text.bytes().collect();
    let mut result = Vec::new();

    let mut i = 0;
    while i < input.len() {
        if i + 2 < input.len() {
            let a = char_to_val(input[i]).unwrap_or(0);
            let b = char_to_val(input[i + 1]).unwrap_or(0);
            let c = char_to_val(input[i + 2]).unwrap_or(0);
            let val = a + b * 45 + c * 45 * 45;
            result.push((val / 256) as u8);
            result.push((val % 256) as u8);
            i += 3;
        } else if i + 1 < input.len() {
            let a = char_to_val(input[i]).unwrap_or(0);
            let b = char_to_val(input[i + 1]).unwrap_or(0);
            let val = a + b * 45;
            result.push(val as u8);
            i += 2;
        } else {
            break;
        }
    }

    result
}
