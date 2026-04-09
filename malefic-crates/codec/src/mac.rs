//! MAC address codec

#[cfg(feature = "encoder")]
use crate::EncodeResult;

#[cfg(feature = "encoder")]
const PAD_BYTE: u8 = 0x90;

#[cfg(feature = "encoder")]
pub fn encode(data: &[u8]) -> EncodeResult {
    let mut padded = data.to_vec();
    while padded.len() % 6 != 0 {
        padded.push(PAD_BYTE);
    }

    let mut macs = Vec::new();
    for chunk in padded.chunks(6) {
        let mac = format!(
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5]
        );
        macs.push(mac);
    }

    EncodeResult {
        encoded: padded,
        key: vec![],
        extra: vec![],
        strings: macs,
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
        for part in line.split('-') {
            if let Ok(b) = u8::from_str_radix(part.trim(), 16) {
                result.push(b);
            }
        }
    }

    result
}
