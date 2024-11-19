use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use std::io::{Cursor, Read, Write};
use crate::crypto::CryptoStream;

// AES-256-CTR type alias
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

#[derive(Clone)]
pub struct AesCtrEncryptor {
    key: [u8; 32],
    iv: [u8; 16],
    encrypt_cipher: Option<Aes256Ctr>,
    decrypt_cipher: Option<Aes256Ctr>,
}
 
impl AesCtrEncryptor {
    pub fn new(key: [u8; 32], iv: [u8; 16]) -> Self {
        let encrypt_cipher = Aes256Ctr::new(&key.into(), &iv.into());
        let decrypt_cipher = Aes256Ctr::new(&key.into(), &iv.into());
        Self {
            key,
            iv,
            encrypt_cipher: Some(encrypt_cipher),
            decrypt_cipher: Some(decrypt_cipher),
        }
    }
    
}

impl CryptoStream for AesCtrEncryptor {
    fn encrypt(&mut self, reader: &mut Cursor<Vec<u8>>, writer: &mut Cursor<Vec<u8>>) -> Result<(), String> {
        let cipher = self.encrypt_cipher.as_mut().ok_or("Cipher not initialized".to_string())?;
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).map_err(|e| e.to_string())?;
        cipher.apply_keystream(&mut buffer);
        writer.write_all(&buffer).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn decrypt(&mut self, reader: &mut Cursor<Vec<u8>>, writer: &mut Cursor<Vec<u8>>) -> Result<(), String> {
        let cipher = self.decrypt_cipher.as_mut().ok_or("Cipher not initialized".to_string())?;
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).map_err(|e| e.to_string())?;
        cipher.apply_keystream(&mut buffer);
        writer.write_all(&buffer).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn reset(&mut self) {
        self.encrypt_cipher = Some(Aes256Ctr::new(&self.key.into(), &self.iv.into()));
        self.decrypt_cipher = Some(Aes256Ctr::new(&self.key.into(), &self.iv.into()));
    }
}
