use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipherSeek, StreamCipher};
use std::io::{Cursor, Read, Write};
use crate::crypto::CryptoStream;

pub struct ChaCha20Encryptor {
    key: [u8; 32],
    iv: [u8; 12],
    encrypt_offset: u64, // 用于加密的偏移量
    decrypt_offset: u64, // 用于解密的偏移量
}

impl ChaCha20Encryptor {
    pub fn new(key: [u8; 32], iv: [u8; 12]) -> Self {
        ChaCha20Encryptor {
            key,
            iv,
            encrypt_offset: 0, // 初始化加密偏移量
            decrypt_offset: 0, // 初始化解密偏移量
        }
    }
}

impl CryptoStream for ChaCha20Encryptor {
    fn encrypt(&mut self, reader: &mut Cursor<Vec<u8>>, writer: &mut Cursor<Vec<u8>>) -> Result<(), String> {
        let mut cipher = ChaCha20::new(&self.key.into(), &self.iv.into());

        // 设置 cipher 的加密偏移
        cipher.seek(self.encrypt_offset);

        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).map_err(|e| e.to_string())?;

        // In-place 加密
        cipher.apply_keystream(&mut buffer);

        // 更新加密偏移量
        self.encrypt_offset += buffer.len() as u64;

        writer.write_all(&buffer).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn decrypt(&mut self, reader: &mut Cursor<Vec<u8>>, writer: &mut Cursor<Vec<u8>>) -> Result<(), String> {
        let mut cipher = ChaCha20::new(&self.key.into(), &self.iv.into());

        // 设置 cipher 的解密偏移
        cipher.seek(self.decrypt_offset);

        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).map_err(|e| e.to_string())?;

        // In-place 解密 (ChaCha20 加解密相同)
        cipher.apply_keystream(&mut buffer);

        // 更新解密偏移量
        self.decrypt_offset += buffer.len() as u64;

        writer.write_all(&buffer).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn reset(&mut self) {
        // 重置加密和解密的偏移量
        self.encrypt_offset = 0;
        self.decrypt_offset = 0;
    }
}
