use age::secrecy::ExposeSecret;
use age::x25519;
use std::str::FromStr;

pub fn generate_age_keypair() -> (String, String) {
    let identity = x25519::Identity::generate();
    let recipient = identity.to_public();
    (
        identity.to_string().expose_secret().to_string(),
        recipient.to_string(),
    )
}

pub fn parse_age_identity(private_key: &str) -> Result<x25519::Identity, String> {
    x25519::Identity::from_str(private_key).map_err(|e| format!("Invalid private key: {}", e))
}

pub fn parse_age_recipient(public_key: &str) -> Result<x25519::Recipient, String> {
    x25519::Recipient::from_str(public_key).map_err(|e| format!("Invalid public key: {}", e))
}

pub fn age_encrypt(data: &[u8], public_key: &str) -> Result<Vec<u8>, String> {
    let recipient = parse_age_recipient(public_key)?;
    age::encrypt(&recipient, data).map_err(|e| format!("Failed to encrypt: {}", e))
}

pub fn age_decrypt(encrypted_data: &[u8], private_key: &str) -> Result<Vec<u8>, String> {
    let identity = parse_age_identity(private_key)?;
    age::decrypt(&identity, encrypted_data).map_err(|e| format!("Failed to decrypt: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_age_encrypt_decrypt_roundtrip() {
        let (private_key, public_key) = generate_age_keypair();
        let plaintext = b"Hello, age encryption!";

        let encrypted = age_encrypt(plaintext, &public_key).expect("encrypt failed");
        assert_ne!(
            encrypted, plaintext,
            "ciphertext must differ from plaintext"
        );
        assert!(
            encrypted.len() > plaintext.len(),
            "ciphertext must be larger than plaintext"
        );

        let decrypted = age_decrypt(&encrypted, &private_key).expect("decrypt failed");
        assert_eq!(
            decrypted, plaintext,
            "round-trip must recover original data"
        );
    }

    #[test]
    fn test_age_bidirectional_communication() {
        let (server_priv, server_pub) = generate_age_keypair();
        let (implant_priv, implant_pub) = generate_age_keypair();

        // Implant -> Server
        let msg = b"implant checkin data";
        let enc = age_encrypt(msg, &server_pub).expect("encrypt to server");
        let dec = age_decrypt(&enc, &server_priv).expect("server decrypt");
        assert_eq!(dec, msg);

        // Server -> Implant
        let msg2 = b"server tasking payload";
        let enc2 = age_encrypt(msg2, &implant_pub).expect("encrypt to implant");
        let dec2 = age_decrypt(&enc2, &implant_priv).expect("implant decrypt");
        assert_eq!(dec2, msg2);
    }

    #[test]
    fn test_age_wrong_key_decrypt_fails() {
        let (_priv_a, pub_a) = generate_age_keypair();
        let (priv_b, _pub_b) = generate_age_keypair();

        let encrypted = age_encrypt(b"secret", &pub_a).expect("encrypt");
        assert!(
            age_decrypt(&encrypted, &priv_b).is_err(),
            "wrong key must fail"
        );
    }

    #[test]
    fn test_age_tamper_detection() {
        let (private_key, public_key) = generate_age_keypair();
        let mut encrypted = age_encrypt(b"integrity data", &public_key).expect("encrypt");

        let mid = encrypted.len() / 2;
        encrypted[mid] ^= 0xFF;

        assert!(
            age_decrypt(&encrypted, &private_key).is_err(),
            "tampered data must fail"
        );
    }

    #[test]
    fn test_age_empty_plaintext() {
        let (private_key, public_key) = generate_age_keypair();
        let encrypted = age_encrypt(b"", &public_key).expect("encrypt empty");
        let decrypted = age_decrypt(&encrypted, &private_key).expect("decrypt empty");
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn test_age_large_payload() {
        let (private_key, public_key) = generate_age_keypair();
        let plaintext: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();

        let encrypted = age_encrypt(&plaintext, &public_key).expect("encrypt large");
        let decrypted = age_decrypt(&encrypted, &private_key).expect("decrypt large");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_age_public_key_derivation() {
        let (private_key, public_key) = generate_age_keypair();
        let identity = parse_age_identity(&private_key).expect("parse identity");
        let derived_pub = identity.to_public().to_string();
        assert_eq!(derived_pub, public_key, "derived public key must match");
    }

    #[test]
    fn test_age_key_exchange_e2e() {
        // Phase 1: Initial keys
        let (server_priv, server_pub) = generate_age_keypair();
        let (implant_priv, implant_pub) = generate_age_keypair();

        // Verify initial bidirectional
        let enc1 = age_encrypt(b"init i2s", &server_pub).unwrap();
        assert_eq!(age_decrypt(&enc1, &server_priv).unwrap(), b"init i2s");
        let enc2 = age_encrypt(b"init s2i", &implant_pub).unwrap();
        assert_eq!(age_decrypt(&enc2, &implant_priv).unwrap(), b"init s2i");

        // Phase 2: Key rotation
        let (new_server_priv, new_server_pub) = generate_age_keypair();
        let req = age_encrypt(new_server_pub.as_bytes(), &implant_pub).unwrap();
        let dec_req = age_decrypt(&req, &implant_priv).unwrap();
        assert_eq!(String::from_utf8(dec_req).unwrap(), new_server_pub);

        // Phase 3: Implant new keypair
        let (new_implant_priv, new_implant_pub) = generate_age_keypair();
        let resp = age_encrypt(new_implant_pub.as_bytes(), &server_pub).unwrap();
        let dec_resp = age_decrypt(&resp, &server_priv).unwrap();
        assert_eq!(String::from_utf8(dec_resp).unwrap(), new_implant_pub);

        // Phase 4: New keys work
        let enc3 = age_encrypt(b"post i2s", &new_server_pub).unwrap();
        assert_eq!(age_decrypt(&enc3, &new_server_priv).unwrap(), b"post i2s");
        let enc4 = age_encrypt(b"post s2i", &new_implant_pub).unwrap();
        assert_eq!(age_decrypt(&enc4, &new_implant_priv).unwrap(), b"post s2i");

        // Phase 5: Old keys fail on new data
        assert!(
            age_decrypt(&enc3, &server_priv).is_err(),
            "old server key must fail"
        );
        assert!(
            age_decrypt(&enc4, &implant_priv).is_err(),
            "old implant key must fail"
        );
    }

    #[test]
    fn test_age_encrypt_decrypt_key_separation() {
        let (server_priv, server_pub) = generate_age_keypair();
        let (implant_priv, _implant_pub) = generate_age_keypair();

        let msg = b"test separation";
        let encrypted = age_encrypt(msg, &server_pub).unwrap();

        // Correct: decrypt with server_priv
        assert_eq!(age_decrypt(&encrypted, &server_priv).unwrap(), msg);

        // Wrong: public key is not a valid identity
        assert!(
            age_decrypt(&encrypted, &server_pub).is_err(),
            "public key must not work as decrypt key"
        );

        // Wrong: unrelated private key
        assert!(
            age_decrypt(&encrypted, &implant_priv).is_err(),
            "unrelated private key must fail"
        );
    }
}
