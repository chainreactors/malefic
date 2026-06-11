//! UUID codec - RFC 4122 byte-reordered UUID string encoding

#[cfg(feature = "encoder")]
use crate::EncodeResult;

#[cfg(feature = "encoder")]
const PAD_BYTE: u8 = 0x90;

#[cfg(feature = "encoder")]
pub fn encode(data: &[u8]) -> EncodeResult {
    let mut padded = data.to_vec();
    while padded.len() % 16 != 0 {
        padded.push(PAD_BYTE);
    }

    let mut uuids = Vec::new();
    for chunk in padded.chunks(16) {
        let uuid = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            chunk[3], chunk[2], chunk[1], chunk[0],
            chunk[5], chunk[4],
            chunk[7], chunk[6],
            chunk[8], chunk[9],
            chunk[10], chunk[11], chunk[12], chunk[13], chunk[14], chunk[15]
        );
        uuids.push(uuid);
    }

    EncodeResult {
        encoded: padded,
        key: vec![],
        extra: vec![],
        strings: uuids,
    }
}

pub fn decode(data: &[u8], _key: &[u8], _extra: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(data);
    let mut result = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let hex: String = line.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() != 32 {
            continue;
        }

        let bytes: Vec<u8> = (0..32)
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
            .collect();

        if bytes.len() >= 16 {
            result.push(bytes[3]);
            result.push(bytes[2]);
            result.push(bytes[1]);
            result.push(bytes[0]);
            result.push(bytes[5]);
            result.push(bytes[4]);
            result.push(bytes[7]);
            result.push(bytes[6]);
            result.extend_from_slice(&bytes[8..16]);
        }
    }

    result
}
