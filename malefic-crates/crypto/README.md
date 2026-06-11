# malefic-crypto

提供流式对称加密/解密与 Snappy 数据压缩能力的轻量级密码学工具库。

## 功能简介

- **流式加密**：基于 `CryptoStream` trait，统一封装多种对称加密算法（AES-256-CTR / ChaCha20 / XOR）
- **数据压缩**：基于 Snappy 算法的快速压缩与解压缩
- **age 加密**：基于 X25519 的非对称加密，支持密钥对生成、加密、解密与密钥轮换
- **编译期算法选择**：通过 feature flag 在编译期选定加密后端，零运行时开销

## Features

| Feature | 说明 |
|---------|------|
| `crypto_aes` | AES-256-CTR 流式加密（默认启用） |
| `crypto_chacha20` | ChaCha20 流式加密 |
| `crypto_xor` | XOR 流式加密 |
| `secure` | 启用 age (X25519) 非对称加密 |

> `crypto_aes`、`crypto_chacha20`、`crypto_xor` 三者互斥，编译时只能选择其一作为 `Cryptor` 后端。

## 核心类型

- **`Cryptor`** - 加密器实例，提供 `encrypt`、`decrypt`、`reset` 方法
- **`CryptoStream`** - 流式加密 trait，所有加密后端均需实现
- **`CryptorError`** - 统一错误类型

## 基本用法

### 对称加密

```rust
use malefic_crypto::crypto::{new_cryptor, Cryptor};

// 创建加密器（key: 32 字节, iv: 16 字节，不足自动填充）
let key = b"my-secret-key".to_vec();
let iv = b"my-iv".to_vec();
let mut cryptor = new_cryptor(key, iv);

// 加密
let plaintext = b"hello world".to_vec();
let ciphertext = cryptor.encrypt(plaintext).unwrap();

// 重置密钥流状态后解密
cryptor.reset();
let decrypted = cryptor.decrypt(ciphertext).unwrap();
assert_eq!(decrypted, b"hello world");
```

### Snappy 压缩

```rust
use malefic_crypto::compress::{compress, decompress};

let data = b"some data to compress";
let compressed = compress(data).unwrap();
let decompressed = decompress(&compressed).unwrap();
assert_eq!(decompressed, data);
```

### age 非对称加密

```rust
use malefic_crypto::crypto::age::*;

// 生成 X25519 密钥对
let (private_key, public_key) = generate_age_keypair();

// 加密
let ciphertext = age_encrypt(b"secret data", &public_key).unwrap();

// 解密
let plaintext = age_decrypt(&ciphertext, &private_key).unwrap();
assert_eq!(plaintext, b"secret data");
```

## 参考链接

- [RustCrypto AES](https://github.com/RustCrypto/block-ciphers/tree/master/aes)
- [RustCrypto ChaCha20](https://github.com/RustCrypto/stream-ciphers/tree/master/chacha20)
- [Snappy (snap crate)](https://github.com/BurntSushi/rust-snappy)
- [age encryption](https://github.com/str4d/rage)
