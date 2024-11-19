use std::io::{Cursor, Read, Write};
use crate::crypto::CryptoStream;

#[derive(Clone)]
pub struct XorEncryptor {
    key: Vec<u8>,
    iv: Vec<u8>,
    encrypt_counter: usize, // 用于加密的计数器
    decrypt_counter: usize, // 用于解密的计数器
}

impl XorEncryptor {
    pub fn new(key: Vec<u8>, iv: Vec<u8>) -> Self {
        XorEncryptor {
            key,
            iv,
            encrypt_counter: 0,
            decrypt_counter: 0,
        }
    }
}

fn xor_process(data: &mut [u8], key: &[u8], iv: &[u8], counter: &mut usize) {
    let key_len = key.len();
    let iv_len = iv.len();

    for (i, byte) in data.iter_mut().enumerate() {
        let index = *counter + i;
        let key_byte = key[index % key_len];
        let iv_byte = iv[index % iv_len];
        *byte ^= key_byte ^ iv_byte; // XOR encryption/decryption
    }

    *counter += data.len();
}

impl CryptoStream for XorEncryptor {
    fn encrypt(&mut self, reader: &mut Cursor<Vec<u8>>, writer: &mut Cursor<Vec<u8>>) -> Result<(), String> {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).map_err(|e| e.to_string())?;

        let key = self.key.clone(); // 克隆 key 和 iv，避免借用冲突
        let iv = self.iv.clone();
        let encrypt_counter = &mut self.encrypt_counter;

        // 提取 xor_process 的逻辑
        xor_process(&mut buffer, &key, &iv, encrypt_counter);

        writer.write_all(&mut buffer).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn decrypt(&mut self, reader: &mut Cursor<Vec<u8>>, writer: &mut Cursor<Vec<u8>>) -> Result<(), String> {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).map_err(|e| e.to_string())?;

        let key = self.key.clone(); // 克隆 key 和 iv，避免借用冲突
        let iv = self.iv.clone();
        let decrypt_counter = &mut self.decrypt_counter;

        // 提取 xor_process 的逻辑
        xor_process(&mut buffer, &key, &iv, decrypt_counter);

        writer.write_all(&mut buffer).map_err(|e| e.to_string())?;
        Ok(())
    }
    
    fn reset(&mut self) {
        self.encrypt_counter = 0;
        self.decrypt_counter = 0;
    }
}
