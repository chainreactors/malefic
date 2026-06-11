pub mod aes2;
pub mod aes_enc;
pub mod base45;
pub mod base58;
pub mod base64_enc;
pub mod chacha;
pub mod des_enc;
pub mod ipv4;
pub mod mac;
pub mod rc4;
pub mod uuid;
pub mod xor;

use anyhow::Result;
use std::fmt;

pub const ENCODING_NAMES: &[&str] = &[
    "xor", "uuid", "mac", "ipv4", "base64", "base45", "base58", "aes", "aes2", "des", "chacha",
    "rc4",
];

#[derive(Debug, Clone)]
pub enum EncodingType {
    Xor,
    Uuid,
    Mac,
    Ipv4,
    Base64,
    Base45,
    Base58,
    Aes,
    Aes2,
    Des,
    ChaCha,
    Rc4,
}

impl EncodingType {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "xor" => Ok(Self::Xor),
            "uuid" => Ok(Self::Uuid),
            "mac" => Ok(Self::Mac),
            "ipv4" => Ok(Self::Ipv4),
            "base64" => Ok(Self::Base64),
            "base45" => Ok(Self::Base45),
            "base58" => Ok(Self::Base58),
            "aes" => Ok(Self::Aes),
            "aes2" => Ok(Self::Aes2),
            "des" => Ok(Self::Des),
            "chacha" => Ok(Self::ChaCha),
            "rc4" => Ok(Self::Rc4),
            _ => anyhow::bail!(
                "Unknown encoding: {}. Use --list to see available encodings.",
                s
            ),
        }
    }
}

impl fmt::Display for EncodingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xor => write!(f, "xor"),
            Self::Uuid => write!(f, "uuid"),
            Self::Mac => write!(f, "mac"),
            Self::Ipv4 => write!(f, "ipv4"),
            Self::Base64 => write!(f, "base64"),
            Self::Base45 => write!(f, "base45"),
            Self::Base58 => write!(f, "base58"),
            Self::Aes => write!(f, "aes"),
            Self::Aes2 => write!(f, "aes2"),
            Self::Des => write!(f, "des"),
            Self::ChaCha => write!(f, "chacha"),
            Self::Rc4 => write!(f, "rc4"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum OutputFormat {
    Bin,
    C,
    Rust,
    All,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "bin" | "binary" => Ok(Self::Bin),
            "c" => Ok(Self::C),
            "rust" | "rs" => Ok(Self::Rust),
            "all" => Ok(Self::All),
            _ => anyhow::bail!("Unknown output format: {}. Use bin, c, rust, or all.", s),
        }
    }
}

/// Result of encoding a payload
pub struct EncodeResult {
    /// The encoded payload bytes
    pub encoded: Vec<u8>,
    /// Key material (if applicable)
    pub key: Vec<u8>,
    /// Additional key material (nonce, IV, etc.)
    pub extra: Vec<u8>,
    /// String-based output (for UUID, MAC, IPv4 encodings)
    pub strings: Vec<String>,
}

/// Encode a payload using the specified method
pub fn encode_payload(data: &[u8], encoding: &EncodingType) -> Result<EncodeResult> {
    match encoding {
        EncodingType::Xor => xor::encode(data),
        EncodingType::Uuid => uuid::encode(data),
        EncodingType::Mac => mac::encode(data),
        EncodingType::Ipv4 => ipv4::encode(data),
        EncodingType::Base64 => base64_enc::encode(data),
        EncodingType::Base45 => base45::encode(data),
        EncodingType::Base58 => base58::encode(data),
        EncodingType::Aes => aes_enc::encode(data),
        EncodingType::Aes2 => aes2::encode(data),
        EncodingType::Des => des_enc::encode(data),
        EncodingType::ChaCha => chacha::encode(data),
        EncodingType::Rc4 => rc4::encode(data),
    }
}

/// Format bytes as C array
pub fn bytes_to_c_array(name: &str, data: &[u8]) -> String {
    let hex_vals: Vec<String> = data.iter().map(|b| format!("0x{:02x}", b)).collect();
    let lines: Vec<String> = hex_vals
        .chunks(16)
        .map(|chunk| format!("    {}", chunk.join(", ")))
        .collect();
    format!("unsigned char {}[] = {{\n{}\n}};", name, lines.join(",\n"))
}

/// Format bytes as Rust array
pub fn bytes_to_rust_array(name: &str, data: &[u8]) -> String {
    let hex_vals: Vec<String> = data.iter().map(|b| format!("0x{:02x}", b)).collect();
    let lines: Vec<String> = hex_vals
        .chunks(16)
        .map(|chunk| format!("    {}", chunk.join(", ")))
        .collect();
    format!("const {}: &[u8] = &[\n{}\n];", name, lines.join(",\n"))
}

/// Format string array as C array
pub fn strings_to_c_array(name: &str, strings: &[String]) -> String {
    let entries: Vec<String> = strings.iter().map(|s| format!("    \"{}\"", s)).collect();
    format!("const char* {}[] = {{\n{}\n}};", name, entries.join(",\n"))
}

/// Format string array as Rust array
pub fn strings_to_rust_array(name: &str, strings: &[String]) -> String {
    let entries: Vec<String> = strings.iter().map(|s| format!("    \"{}\"", s)).collect();
    format!("const {}: &[&str] = &[\n{}\n];", name, entries.join(",\n"))
}

/// Format the encode result for output
pub fn format_output(
    result: &EncodeResult,
    encoding: &EncodingType,
    format: &OutputFormat,
) -> String {
    match format {
        OutputFormat::Bin | OutputFormat::All => {
            // Binary format is handled separately (written as raw bytes)
            // All is handled by the caller
            String::new()
        }
        OutputFormat::C => format_c(result, encoding),
        OutputFormat::Rust => format_rust(result, encoding),
    }
}

fn format_c(result: &EncodeResult, encoding: &EncodingType) -> String {
    match encoding {
        EncodingType::Xor => {
            let key = bytes_to_c_array("XORkey", &result.key);
            let data = bytes_to_c_array("XORed", &result.encoded);
            format!("{}\n\n{}", key, data)
        }
        EncodingType::Uuid => strings_to_c_array("UUIDs", &result.strings),
        EncodingType::Mac => strings_to_c_array("MAC", &result.strings),
        EncodingType::Ipv4 => strings_to_c_array("IPv4s", &result.strings),
        EncodingType::Base64 | EncodingType::Base45 | EncodingType::Base58 => {
            let s = &result.strings[0];
            format!("const char {}[] = \"{}\";", encoding, s)
        }
        EncodingType::Aes | EncodingType::Aes2 => {
            let key = bytes_to_c_array("AESkey", &result.key);
            let data = bytes_to_c_array("magiccode", &result.encoded);
            format!("{}\n\n{}", key, data)
        }
        EncodingType::Des => {
            let key = bytes_to_c_array("DESkey", &result.key);
            let data = bytes_to_c_array("magiccode", &result.encoded);
            format!("{}\n\n{}", key, data)
        }
        EncodingType::ChaCha => {
            let key = bytes_to_c_array("CHACHAkey", &result.key);
            let nonce = bytes_to_c_array("CHACHAnonce", &result.extra);
            let data = bytes_to_c_array("magiccode", &result.encoded);
            format!("{}\n\n{}\n\n{}", key, nonce, data)
        }
        EncodingType::Rc4 => {
            let key = bytes_to_c_array("RC4key", &result.key);
            let data = bytes_to_c_array("magiccode", &result.encoded);
            format!("{}\n\n{}", key, data)
        }
    }
}

fn format_rust(result: &EncodeResult, encoding: &EncodingType) -> String {
    match encoding {
        EncodingType::Xor => {
            let key = bytes_to_rust_array("XOR_KEY", &result.key);
            let data = bytes_to_rust_array("XORED", &result.encoded);
            format!("{}\n\n{}", key, data)
        }
        EncodingType::Uuid => strings_to_rust_array("UUIDS", &result.strings),
        EncodingType::Mac => strings_to_rust_array("MACS", &result.strings),
        EncodingType::Ipv4 => strings_to_rust_array("IPV4S", &result.strings),
        EncodingType::Base64 | EncodingType::Base45 | EncodingType::Base58 => {
            let s = &result.strings[0];
            format!(
                "const {}: &str = \"{}\";",
                encoding.to_string().to_uppercase(),
                s
            )
        }
        EncodingType::Aes | EncodingType::Aes2 => {
            let key = bytes_to_rust_array("AES_KEY", &result.key);
            let data = bytes_to_rust_array("ENCODED", &result.encoded);
            format!("{}\n\n{}", key, data)
        }
        EncodingType::Des => {
            let key = bytes_to_rust_array("DES_KEY", &result.key);
            let data = bytes_to_rust_array("ENCODED", &result.encoded);
            format!("{}\n\n{}", key, data)
        }
        EncodingType::ChaCha => {
            let key = bytes_to_rust_array("CHACHA_KEY", &result.key);
            let nonce = bytes_to_rust_array("CHACHA_NONCE", &result.extra);
            let data = bytes_to_rust_array("ENCODED", &result.encoded);
            format!("{}\n\n{}\n\n{}", key, nonce, data)
        }
        EncodingType::Rc4 => {
            let key = bytes_to_rust_array("RC4_KEY", &result.key);
            let data = bytes_to_rust_array("ENCODED", &result.encoded);
            format!("{}\n\n{}", key, data)
        }
    }
}
