//! Base58 codec (Bitcoin alphabet)

#[cfg(feature = "encoder")]
use crate::EncodeResult;

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn char_to_val(c: u8) -> Option<u8> {
    BASE58_ALPHABET
        .iter()
        .position(|&b| b == c)
        .map(|p| p as u8)
}

#[cfg(feature = "encoder")]
pub fn encode(data: &[u8]) -> EncodeResult {
    let mut leading_zeros = 0;
    for &byte in data {
        if byte == 0 {
            leading_zeros += 1;
        } else {
            break;
        }
    }

    let mut digits: Vec<u8> = vec![0];
    for &byte in data {
        let mut carry = byte as u32;
        for digit in digits.iter_mut() {
            carry += (*digit as u32) * 256;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut result = String::new();
    for _ in 0..leading_zeros {
        result.push('1');
    }
    for &digit in digits.iter().rev() {
        result.push(BASE58_ALPHABET[digit as usize] as char);
    }

    EncodeResult {
        encoded: result.as_bytes().to_vec(),
        key: vec![],
        extra: vec![],
        strings: vec![result],
    }
}

pub fn decode(data: &[u8], _key: &[u8], _extra: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(data);
    let input = text.trim();

    let mut leading_ones = 0;
    for c in input.chars() {
        if c == '1' {
            leading_ones += 1;
        } else {
            break;
        }
    }

    let mut digits: Vec<u8> = vec![0];
    for c in input.bytes() {
        let val = match char_to_val(c) {
            Some(v) => v as u32,
            None => continue,
        };

        let mut carry = val;
        for digit in digits.iter_mut() {
            carry += (*digit as u32) * 58;
            *digit = (carry % 256) as u8;
            carry /= 256;
        }
        while carry > 0 {
            digits.push((carry % 256) as u8);
            carry /= 256;
        }
    }

    let mut result = Vec::with_capacity(leading_ones + digits.len());
    for _ in 0..leading_ones {
        result.push(0);
    }
    for &d in digits.iter().rev() {
        result.push(d);
    }

    result
}
