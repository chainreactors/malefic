use crate::crypto::CryptoStream;
use std::io::{Cursor, Read, Write};

#[derive(Clone)]
pub struct XorEncryptor {
    key: Vec<u8>,
    iv: Vec<u8>,
    encrypt_counter: usize,
    decrypt_counter: usize,
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
        *byte ^= key[index % key_len] ^ iv[index % iv_len];
    }
    *counter += data.len();
}

impl CryptoStream for XorEncryptor {
    fn encrypt(
        &mut self,
        reader: &mut Cursor<Vec<u8>>,
        writer: &mut Cursor<Vec<u8>>,
    ) -> Result<(), String> {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).map_err(|e| e.to_string())?;
        let key = self.key.clone();
        let iv = self.iv.clone();
        xor_process(&mut buffer, &key, &iv, &mut self.encrypt_counter);
        writer.write_all(&mut buffer).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn decrypt(
        &mut self,
        reader: &mut Cursor<Vec<u8>>,
        writer: &mut Cursor<Vec<u8>>,
    ) -> Result<(), String> {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).map_err(|e| e.to_string())?;
        let key = self.key.clone();
        let iv = self.iv.clone();
        xor_process(&mut buffer, &key, &iv, &mut self.decrypt_counter);
        writer.write_all(&mut buffer).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn reset(&mut self) {
        self.encrypt_counter = 0;
        self.decrypt_counter = 0;
    }
}
