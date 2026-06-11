use crate::crypto::CryptoStream;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use std::io::{Cursor, Read, Write};

pub struct ChaCha20Encryptor {
    key: [u8; 32],
    iv: [u8; 12],
    encrypt_offset: u64,
    decrypt_offset: u64,
}

impl ChaCha20Encryptor {
    pub fn new(key: [u8; 32], iv: [u8; 12]) -> Self {
        ChaCha20Encryptor {
            key,
            iv,
            encrypt_offset: 0,
            decrypt_offset: 0,
        }
    }
}

impl CryptoStream for ChaCha20Encryptor {
    fn encrypt(
        &mut self,
        reader: &mut Cursor<Vec<u8>>,
        writer: &mut Cursor<Vec<u8>>,
    ) -> Result<(), String> {
        let mut cipher = ChaCha20::new(&self.key.into(), &self.iv.into());
        cipher.seek(self.encrypt_offset);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).map_err(|e| e.to_string())?;
        cipher.apply_keystream(&mut buffer);
        self.encrypt_offset += buffer.len() as u64;
        writer.write_all(&buffer).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        reader: &mut Cursor<Vec<u8>>,
        writer: &mut Cursor<Vec<u8>>,
    ) -> Result<(), String> {
        let mut cipher = ChaCha20::new(&self.key.into(), &self.iv.into());
        cipher.seek(self.decrypt_offset);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).map_err(|e| e.to_string())?;
        cipher.apply_keystream(&mut buffer);
        self.decrypt_offset += buffer.len() as u64;
        writer.write_all(&buffer).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn reset(&mut self) {
        self.encrypt_offset = 0;
        self.decrypt_offset = 0;
    }
}
