#[cfg(test)]
mod tests {
    use malefic_proto::crypto::age::{age_decrypt, age_encrypt, generate_age_keypair, parse_age_identity, parse_age_recipient};
    use super::*;

    // 测试用的固定密钥对
    const TEST_PRIVATE_KEY: &str = "AGE-SECRET-KEY-1NHEED05N64AGNN7EU7U3ZZGPJ96DE9TJ4PT0V2J3NRHJTHD42S9SVKLSFG";
    const TEST_PUBLIC_KEY: &str = "age1kzyvhtd5hncrv2xnu8z6f95a90rlgt5e7lr9qkry0eygx5ygxd7qj67evy";

    #[test]
    fn test_generate_age_keypair() {
        let (private_key, public_key) = generate_age_keypair();

        // 验证密钥不为空
        assert!(!private_key.is_empty());
        assert!(!public_key.is_empty());

        // 验证私钥格式
        assert!(private_key.starts_with("AGE-SECRET-KEY-"));

        // 验证公钥格式
        assert!(public_key.starts_with("age"));

        // 验证生成的密钥可以正确解析
        assert!(parse_age_identity(&private_key).is_ok());
        assert!(parse_age_recipient(&public_key).is_ok());
    }

    #[test]
    fn test_age_encrypt_decrypt_with_test_keys() {
        let test_data = b"Hello, Age encryption test!";

        // 使用测试密钥对进行加密
        let encrypted_result = age_encrypt(test_data, TEST_PUBLIC_KEY);
        assert!(encrypted_result.is_ok());
        println!("encrypted_result: {:?}", encrypted_result);
        let encrypted_data = encrypted_result.unwrap();
        // [97 103 101 45 101 110 99 114 121 112 116 105 111 110 46 111 114 103 47 118 49 10 45 62 32 88 50 53 53 49 57 32 77 107 69 112 66 118 72 57 112 71 115 114 110 53 65 87 106 78 51 77 119 114 55 78 106 106 101 49 111 85 114 53 50 115 118 53 57 49 116 105 51 106 77 10 80 79 65 78 90 55 122 119 107 83 77 121 53 106 110 109 108 73 78 82 74 50 74 48 109 57 102 67 97 55 82 48 81 122 43 78 114 51 49 90 73 78 103 10 45 45 45 32 103 89 47 102 74 120 66 111 77 105 76 49 82 113 79 117 106 86 55 82 114 118 98 84 66 55 78 84 98 117 78 85 67 81 49 97 68 79 106 113 90 72 103 10 236 250 185 201 8 170 176 15 3 116 166 58 207 17 11 20 14 97 192 99 191 60 191 68 188 255 117 69 239 58 44 138 51 107 182 117 22 255 53 206 99 255 228 164 181 7 0 95 207 85 230 251 127 114 230 253 67 152 229]
        let encrypted_data = vec![97, 103, 101, 45, 101, 110, 99, 114, 121, 112, 116, 105, 111, 110, 46, 111, 114, 103, 47, 118, 49, ];
        assert!(!encrypted_data.is_empty());
        assert_ne!(encrypted_data, test_data.to_vec());

        // 使用测试私钥进行解密
        let decrypted_result = age_decrypt(&encrypted_data, TEST_PRIVATE_KEY);
        assert!(decrypted_result.is_ok());

        let decrypted_data = decrypted_result.unwrap();
        assert_eq!(decrypted_data, test_data);
    }

    #[test]
    fn test_age_encrypt_decrypt_with_generated_keys() {
        let test_data = b"This is a test message for Age encryption.";

        // 生成新的密钥对
        let (private_key, public_key) = generate_age_keypair();

        // 加密
        let encrypted_result = age_encrypt(test_data, &public_key);
        assert!(encrypted_result.is_ok());

        let encrypted_data = encrypted_result.unwrap();
        assert!(!encrypted_data.is_empty());
        assert_ne!(encrypted_data, test_data.to_vec());

        // 解密
        let decrypted_result = age_decrypt(&encrypted_data, &private_key);
        assert!(decrypted_result.is_ok());

        let decrypted_data = decrypted_result.unwrap();
        assert_eq!(decrypted_data, test_data);
    }

    #[test]
    fn test_age_encrypt_multiple_recipients() {
        let test_data = b"Multi-recipient test message";

        // 生成两个密钥对
        let (private_key1, public_key1) = generate_age_keypair();
        let (private_key2, public_key2) = generate_age_keypair();

        // 使用多个接收者进行加密
        let encrypted_result = age_encrypt(test_data, &public_key1);
        assert!(encrypted_result.is_ok());

        let encrypted_data = encrypted_result.unwrap();

        // 使用第一个私钥解密
        let decrypted_result1 = age_decrypt(&encrypted_data, &private_key1);
        assert!(decrypted_result1.is_ok());
        assert_eq!(decrypted_result1.unwrap(), test_data);

        // 使用第二个私钥解密
        let decrypted_result2 = age_decrypt(&encrypted_data, &private_key2);
        assert!(decrypted_result2.is_ok());
        assert_eq!(decrypted_result2.unwrap(), test_data);
    }

    #[test]
    fn test_age_encrypt_with_invalid_public_key() {
        let test_data = b"Test data";
        let invalid_public_key = "invalid-public-key";

        let result = age_encrypt(test_data, invalid_public_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_age_decrypt_with_invalid_private_key() {
        let test_data = b"Test data for invalid key test";

        // 先用有效密钥加密
        let encrypted_data = age_encrypt(test_data, TEST_PUBLIC_KEY).unwrap();

        // 使用无效私钥解密
        let invalid_private_key = "invalid-private-key";
        let result = age_decrypt(&encrypted_data, invalid_private_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_age_decrypt_with_wrong_private_key() {
        let test_data = b"Test data for wrong key test";

        // 生成两个不同的密钥对
        let (_, public_key1) = generate_age_keypair();
        let (private_key2, _) = generate_age_keypair();

        // 用第一个公钥加密
        let encrypted_data = age_encrypt(test_data, &public_key1).unwrap();

        // 用第二个私钥解密（应该失败）
        let result = age_decrypt(&encrypted_data, &private_key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_age_encrypt_empty_data() {
        let empty_data = b"";

        let result = age_encrypt(empty_data, TEST_PUBLIC_KEY);
        assert!(result.is_ok());

        let encrypted_data = result.unwrap();
        let decrypted_result = age_decrypt(&encrypted_data, TEST_PRIVATE_KEY);
        assert!(decrypted_result.is_ok());
        assert_eq!(decrypted_result.unwrap(), empty_data);
    }

    #[test]
    fn test_age_encrypt_large_data() {
        // 测试较大的数据
        let large_data = vec![0x42u8; 1024 * 1024]; // 1MB of data

        let encrypted_result = age_encrypt(&large_data, TEST_PUBLIC_KEY);
        assert!(encrypted_result.is_ok());

        let encrypted_data = encrypted_result.unwrap();
        let decrypted_result = age_decrypt(&encrypted_data, TEST_PRIVATE_KEY);
        assert!(decrypted_result.is_ok());

        let decrypted_data = decrypted_result.unwrap();
        assert_eq!(decrypted_data, large_data);
    }
}