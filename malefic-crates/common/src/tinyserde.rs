extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};
use core::fmt;

#[derive(Debug)]
pub enum Error {
    UnexpectedEof,
    InvalidUtf8,
    InvalidTag(u8),
    TrailingBytes,
    DecryptionFailed,
    TypeMismatch(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedEof => write!(f, "Unexpected end of file"),
            Error::InvalidUtf8 => write!(f, "Invalid UTF-8 sequence"),
            Error::InvalidTag(t) => write!(f, "Invalid tag encountered: 0x{:02x}", t),
            Error::TrailingBytes => write!(f, "Data remains after deserialization"),
            Error::DecryptionFailed => write!(f, "Decryption failed or integrity check error"),
            Error::TypeMismatch(expected) => write!(f, "Expected type: {}", expected),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

pub trait Cipher {
    fn encrypt(&self, input: &[u8], output: &mut Vec<u8>);
    fn decrypt(&self, input: &[u8], output: &mut Vec<u8>) -> Result<()>;
}

pub struct XorCipher {
    seed: u64,
}

impl XorCipher {
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }

    fn next_u8(state: &mut u64) -> u8 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x as u8
    }

    fn process(seed: u64, input: &[u8], output: &mut Vec<u8>) {
        let mut state = seed;
        output.reserve(input.len());
        for &b in input {
            output.push(b ^ Self::next_u8(&mut state));
        }
    }
}

impl Cipher for XorCipher {
    fn encrypt(&self, input: &[u8], output: &mut Vec<u8>) {
        Self::process(self.seed, input, output);
    }

    fn decrypt(&self, input: &[u8], output: &mut Vec<u8>) -> Result<()> {
        Self::process(self.seed, input, output);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    Seq(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

mod tags {
    pub const NULL: u8 = 0x00;
    pub const FALSE: u8 = 0x01;
    pub const TRUE: u8 = 0x02;
    pub const INT: u8 = 0x03;
    pub const FLOAT: u8 = 0x04;
    pub const STR: u8 = 0x05;
    pub const BYTES: u8 = 0x06;
    pub const SEQ: u8 = 0x07;
    pub const MAP: u8 = 0x08;
}

impl Value {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf);
        buf
    }

    pub fn to_bytes_encrypted<C: Cipher>(&self, cipher: &C) -> Vec<u8> {
        let mut plain = Vec::new();
        self.encode_into(&mut plain);

        let mut encrypted = Vec::with_capacity(plain.len());
        cipher.encrypt(&plain, &mut encrypted);
        encrypted
    }

    fn encode_into(&self, buf: &mut Vec<u8>) {
        use tags::*;
        match self {
            Value::Null => buf.push(NULL),
            Value::Bool(false) => buf.push(FALSE),
            Value::Bool(true) => buf.push(TRUE),
            Value::Int(n) => {
                buf.push(INT);
                buf.extend_from_slice(&n.to_le_bytes());
            }
            Value::Float(f) => {
                buf.push(FLOAT);
                buf.extend_from_slice(&f.to_le_bytes());
            }
            Value::Str(s) => {
                buf.push(STR);
                encode_varint(buf, s.len());
                buf.extend_from_slice(s.as_bytes());
            }
            Value::Bytes(b) => {
                buf.push(BYTES);
                encode_varint(buf, b.len());
                buf.extend_from_slice(b);
            }
            Value::Seq(seq) => {
                buf.push(SEQ);
                encode_varint(buf, seq.len());
                for item in seq {
                    item.encode_into(buf);
                }
            }
            Value::Map(map) => {
                buf.push(MAP);
                encode_varint(buf, map.len());
                for (k, v) in map {
                    encode_varint(buf, k.len());
                    buf.extend_from_slice(k.as_bytes());
                    v.encode_into(buf);
                }
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let val = cursor.decode()?;
        if !cursor.is_empty() {
            return Err(Error::TrailingBytes);
        }
        Ok(val)
    }

    pub fn from_bytes_encrypted<C: Cipher>(bytes: &[u8], cipher: &C) -> Result<Self> {
        let mut plain = Vec::with_capacity(bytes.len());
        cipher.decrypt(bytes, &mut plain)?;
        Self::from_bytes(&plain)
    }
}

fn encode_varint(buf: &mut Vec<u8>, mut n: usize) {
    while n >= 0x80 {
        buf.push((n as u8) | 0x80);
        n >>= 7;
    }
    buf.push(n as u8);
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos < self.data.len() {
            let b = self.data[self.pos];
            self.pos += 1;
            Ok(b)
        } else {
            Err(Error::UnexpectedEof)
        }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.pos + len <= self.data.len() {
            let slice = &self.data[self.pos..self.pos + len];
            self.pos += len;
            Ok(slice)
        } else {
            Err(Error::UnexpectedEof)
        }
    }

    fn read_varint(&mut self) -> Result<usize> {
        let mut n: usize = 0;
        let mut shift = 0;
        loop {
            let b = self.read_u8()?;
            n |= ((b & 0x7F) as usize) << shift;
            if (b & 0x80) == 0 {
                return Ok(n);
            }
            shift += 7;
            if shift > 64 {
                return Err(Error::DecryptionFailed);
            }
        }
    }

    fn decode(&mut self) -> Result<Value> {
        use tags::*;
        let tag = self.read_u8()?;
        match tag {
            NULL => Ok(Value::Null),
            FALSE => Ok(Value::Bool(false)),
            TRUE => Ok(Value::Bool(true)),
            INT => {
                let bytes = self.read_exact(8)?;
                Ok(Value::Int(i64::from_le_bytes(bytes.try_into().unwrap())))
            }
            FLOAT => {
                let bytes = self.read_exact(8)?;
                Ok(Value::Float(f64::from_le_bytes(bytes.try_into().unwrap())))
            }
            STR => {
                let len = self.read_varint()?;
                let bytes = self.read_exact(len)?;
                let s = alloc::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
                Ok(Value::Str(s.to_string()))
            }
            BYTES => {
                let len = self.read_varint()?;
                let bytes = self.read_exact(len)?;
                Ok(Value::Bytes(bytes.to_vec()))
            }
            SEQ => {
                let len = self.read_varint()?;
                let mut seq = Vec::with_capacity(len);
                for _ in 0..len {
                    seq.push(self.decode()?);
                }
                Ok(Value::Seq(seq))
            }
            MAP => {
                let len = self.read_varint()?;
                let mut map = BTreeMap::new();
                for _ in 0..len {
                    let k_len = self.read_varint()?;
                    let k_bytes = self.read_exact(k_len)?;
                    let k = alloc::str::from_utf8(k_bytes).map_err(|_| Error::InvalidUtf8)?;
                    let v = self.decode()?;
                    map.insert(k.to_string(), v);
                }
                Ok(Value::Map(map))
            }
            t => Err(Error::InvalidTag(t)),
        }
    }
}

impl TryFrom<Value> for i64 {
    type Error = Error;
    fn try_from(v: Value) -> Result<Self> {
        if let Value::Int(n) = v {
            Ok(n)
        } else {
            Err(Error::TypeMismatch("i64"))
        }
    }
}

impl TryFrom<Value> for String {
    type Error = Error;
    fn try_from(v: Value) -> Result<Self> {
        if let Value::Str(s) = v {
            Ok(s)
        } else {
            Err(Error::TypeMismatch("String"))
        }
    }
}

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Int(v as i64)
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::Int(v)
    }
}

impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::Float(v)
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::Str(v.to_string())
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::Str(v)
    }
}

impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Value::Bytes(v)
    }
}

#[macro_export]
macro_rules! val {
    (null) => { $crate::tinyserde::Value::Null };
    ([ $( $elem:tt ),* ]) => {
        $crate::tinyserde::Value::Seq(alloc::vec![ $( $crate::val!($elem) ),* ])
    };
    ({ $( $key:tt : $val:tt ),* }) => {
        {
            let mut m = alloc::collections::BTreeMap::new();
            $( m.insert(alloc::string::String::from($key), $crate::val!($val)); )*
            $crate::tinyserde::Value::Map(m)
        }
    };
    ($other:expr) => { $crate::tinyserde::Value::from($other) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::val;

    #[test]
    fn test_full_flow() {
        let config = val!({
            "id": 101,
            "name": "RustyConfig",
            "features": ["secure", "fast"],
            "meta": { "active": true }
        });

        let key = 0x1234_5678_9ABC_DEF0;
        let cipher = XorCipher::new(key);

        let encrypted_bytes = config.to_bytes_encrypted(&cipher);
        let plain_bytes = config.to_bytes();

        assert_ne!(encrypted_bytes, plain_bytes);

        let decoded = Value::from_bytes_encrypted(&encrypted_bytes, &cipher)
            .expect("Should decrypt successfully");

        assert_eq!(config, decoded);
    }

    #[test]
    fn test_type_conversion() {
        use core::convert::TryInto;

        let v = val!(42);
        let n: i64 = v.try_into().unwrap();
        assert_eq!(n, 42);
    }
}
