use std::str::FromStr;
use age::x25519;
use age::secrecy::ExposeSecret;

/// 生成新的Age密钥对
pub fn generate_age_keypair() -> (String, String) {
    let identity = x25519::Identity::generate();
    let recipient = identity.to_public();
    (identity.to_string().expose_secret().to_string(), recipient.to_string())
}

/// 从字符串解析Age身份
pub fn parse_age_identity(private_key: &str) -> Result<x25519::Identity, String> {
    x25519::Identity::from_str(private_key)
        .map_err(|e| format!("Invalid private key: {}", e))
}

/// 从字符串解析Age接收者
pub fn parse_age_recipient(public_key: &str) -> Result<x25519::Recipient, String> {
    x25519::Recipient::from_str(public_key)
        .map_err(|e| format!("Invalid public key: {}", e))
}

/// Age加密函数
pub fn age_encrypt(data: &[u8], public_key: &str) -> Result<Vec<u8>, String> {
    let recipient = parse_age_recipient(public_key)?;
    
    age::encrypt(&recipient, data)
        .map_err(|e| format!("Failed to encrypt: {}", e))
}

/// Age解密函数
pub fn age_decrypt(encrypted_data: &[u8], private_key: &str) -> Result<Vec<u8>, String> {
    let identity = parse_age_identity(private_key)?;
    
    age::decrypt(&identity, encrypted_data)
        .map_err(|e| format!("Failed to decrypt: {}", e))
}

