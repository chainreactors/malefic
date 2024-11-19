#![allow(unused_imports)]
use std::io::{Cursor, Read, Write};
use malefic_proto::crypto::CryptoStream;

#[cfg(feature = "Crypto_AES")]
#[test]
fn test_aes() {
    use malefic_proto::crypto::aes::AesCtrEncryptor;
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ]; // 与 Golang 中相同的 key
    let iv = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ]; // 与 Golang 中相同的 iv

    let mut crypto = AesCtrEncryptor::new(key, iv);

    let plaintext = b"1234".to_vec();
    let mut reader = Cursor::new(plaintext.clone());
    let mut writer = Cursor::new(Vec::new());

    // Encrypt
    crypto.encrypt(&mut reader, &mut writer).expect("Encryption failed");
    let ciphertext = writer.into_inner();
    println!("{:?}", ciphertext);

    let mut reader = Cursor::new(plaintext.clone());
    let mut writer = Cursor::new(Vec::new());

    // Encrypt
    crypto.encrypt(&mut reader, &mut writer).expect("Encryption failed");
    let ciphertext = writer.into_inner();
    println!("{:?}", ciphertext);

    // Decrypt
    let mut reader = Cursor::new(ciphertext);
    let mut writer = Cursor::new(Vec::new());
    crypto.decrypt(&mut reader, &mut writer).expect("Decryption failed");

    let decrypted_text = writer.into_inner();
    assert_eq!(plaintext, decrypted_text, "Decrypted text does not match original");
}

#[cfg(feature = "Crypto_Chacha20")]
#[test]
fn test_chacha20() {
    use malefic_proto::crypto::chacha20::ChaCha20Encryptor;
    let key = [0u8; 32]; // Example key, should be generated securely
    let iv = [1u8; 12]; // Fixed IV for test purposes

    let mut encryptor = ChaCha20Encryptor::new(key, iv);

    let plaintext = b"Hello, ChaCha20!".to_vec();
    let mut reader = Cursor::new(plaintext.clone());
    let mut writer = Cursor::new(Vec::new());

    // Encrypt
    encryptor.encrypt(&mut reader, &mut writer).expect("Encryption failed");
    let ciphertext = writer.into_inner();

    // Decrypt
    let mut reader = Cursor::new(ciphertext);
    let mut writer = Cursor::new(Vec::new());
    encryptor.decrypt(&mut reader, &mut writer).expect("Decryption failed");

    let decrypted_text = writer.into_inner();
    assert_eq!(plaintext, decrypted_text, "Decrypted text does not match original");
}

#[cfg(feature = "Crypto_XOR")]
#[test]
fn test_xor() {
    use malefic_proto::crypto::xor::XorEncryptor;

    let key = vec![0u8, 1];
    let iv = vec![0u8, 1]; 

    let mut encryptor = XorEncryptor::new(key, iv);

    let plaintext = b"Hello, XOR encryption!".to_vec(); // 测试用的明文，与 Golang 一致
    let mut reader = Cursor::new(plaintext.clone());
    let mut writer = Cursor::new(Vec::new());

    // 加密
    encryptor.encrypt(&mut reader, &mut writer).expect("Encryption failed");
    let ciphertext = writer.into_inner();
    println!("Ciphertext: {:?}", ciphertext);

    // 解密
    let mut reader = Cursor::new(ciphertext);
    let mut writer = Cursor::new(Vec::new());
    encryptor.decrypt(&mut reader, &mut writer).expect("Decryption failed");

    let decrypted_text = writer.into_inner();
    assert_eq!(plaintext, decrypted_text, "Decrypted text does not match original");
}
