#[cfg(feature = "crypto_aes")]
pub mod aes;
#[cfg(feature = "secure")]
pub mod age;
#[cfg(feature = "crypto_chacha20")]
pub mod chacha20;
#[cfg(feature = "crypto_xor")]
pub mod xor;

#[derive(Error, Debug)]
pub enum CryptorError {
    #[error("Encrypt error, {0}")]
    EncryptError(String),
    #[error("Decrypt error, {0}")]
    DecryptError(String),
    #[error("I/O error, {0}")]
    IO(#[from] std::io::Error),
}

pub trait CryptoStream: Send + Sync {
    fn encrypt(
        &mut self,
        reader: &mut std::io::Cursor<Vec<u8>>,
        writer: &mut std::io::Cursor<Vec<u8>>,
    ) -> Result<(), String>;
    fn decrypt(
        &mut self,
        reader: &mut std::io::Cursor<Vec<u8>>,
        writer: &mut std::io::Cursor<Vec<u8>>,
    ) -> Result<(), String>;
    fn reset(&mut self);
}

use std::vec::Vec;
use thiserror::Error;

cfg_if::cfg_if! {
    if #[cfg(feature = "crypto_aes")] {
        pub use aes::AesCtrEncryptor as cryptor;
        pub fn new_cryptor(key: Vec<u8>, iv: Vec<u8>) -> Cryptor {
            let key_array: [u8; 32] = pkcs7_pad(key, 32).try_into().expect("Invalid key length for AES");
            let iv_array: [u8; 16] = pkcs7_pad(iv, 16).try_into().expect("Invalid IV length for AES");
            Cryptor{cryptor: cryptor::new(key_array, iv_array)}
        }
    } else if #[cfg(feature = "crypto_xor")] {
        pub use xor::XorEncryptor as cryptor;
        pub fn new_cryptor(key: Vec<u8>, iv: Vec<u8>) -> Cryptor {
            Cryptor{cryptor: cryptor::new(key, iv)}
        }
    } else {
        compile_error!("No cryptor selected");
    }
}

#[derive(Clone)]
pub struct Cryptor {
    pub cryptor: cryptor,
}

impl Cryptor {
    pub fn encrypt(&mut self, data: Vec<u8>) -> Result<Vec<u8>, CryptorError> {
        let mut reader = std::io::Cursor::new(data);
        let mut writer = std::io::Cursor::new(Vec::new());
        self.cryptor
            .encrypt(&mut reader, &mut writer)
            .map_err(|e| CryptorError::EncryptError(e))?;
        Ok(writer.into_inner())
    }

    pub fn decrypt(&mut self, data: Vec<u8>) -> Result<Vec<u8>, CryptorError> {
        let mut reader = std::io::Cursor::new(data);
        let mut writer = std::io::Cursor::new(Vec::new());
        self.cryptor
            .decrypt(&mut reader, &mut writer)
            .map_err(|e| CryptorError::DecryptError(e))?;
        Ok(writer.into_inner())
    }

    pub fn reset(&mut self) {
        self.cryptor.reset();
    }
}

pub fn pkcs7_pad(mut data: Vec<u8>, block_size: usize) -> Vec<u8> {
    if data.len() >= block_size {
        data.truncate(block_size);
        return data;
    }
    let padding = block_size - data.len();
    data.extend(vec![0u8; padding]);
    data
}
