# malefic-codec

纯 Rust 实现的 12 种对称编解码算法库，用于 payload 混淆与还原。

## 功能简介

- 提供 12 种编解码算法，涵盖加密、编码、格式伪装三大类
- 所有算法均为纯 Rust 实现，零 C 依赖
- 编码端（`encoder`）自动生成随机密钥；解码端仅需 `decode(data, key, extra)`
- 通过 feature gate 按需编译，最小化二进制体积
- 统一的 `EncodeResult` 输出结构，包含密文、密钥、附加材料和字符串表示

## 算法分类

**加密类** -- 使用密钥进行对称加解密：

| 算法 | 说明 |
|------|------|
| XOR | 单字节异或 |
| AES | AES-256-CBC，SHA256 派生密钥，零 IV |
| AES2 | 与 AES 相同算法，CLI 输出格式不同 |
| DES | DES-ECB，7 字节密钥扩展为 8 字节（含奇偶校验位） |
| ChaCha20 | 32 字节密钥 + 12 字节 nonce |
| RC4 | 16 字节密钥流密码 |

**编码类** -- 无密钥的可逆编码：

| 算法 | 说明 |
|------|------|
| Base64 | 标准 Base64 编解码 |
| Base45 | Base45 编解码 |
| Base58 | Base58 编解码 |

**格式伪装类** -- 将字节流编码为常见网络格式字符串：

| 算法 | 说明 |
|------|------|
| UUID | 按 RFC 4122 字节序重排，每 16 字节生成一个 UUID 字符串 |
| MAC | 每 6 字节生成一个 MAC 地址字符串 |
| IPv4 | 每 4 字节生成一个 IPv4 地址字符串 |

## Features

| Feature | 说明 |
|---------|------|
| `encoder` | 启用编码端（`encode` 函数），引入 `rand` 用于密钥生成 |
| `codec_xor` | XOR 编解码 |
| `codec_aes` | AES-256-CBC 编解码 |
| `codec_aes2` | AES2 编解码（依赖 `codec_aes`） |
| `codec_des` | DES-ECB 编解码 |
| `codec_chacha` | ChaCha20 编解码 |
| `codec_rc4` | RC4 编解码 |
| `codec_base64` | Base64 编解码 |
| `codec_base45` | Base45 编解码 |
| `codec_base58` | Base58 编解码 |
| `codec_uuid` | UUID 格式伪装 |
| `codec_mac` | MAC 地址格式伪装 |
| `codec_ipv4` | IPv4 地址格式伪装 |
| `codec_all` | 启用全部 12 种算法 |

## 基本用法

```rust
// 编码端（需启用 encoder + 对应算法 feature）
let result = malefic_codec::xor::encode(payload);
// result.encoded  -- 编码后的字节
// result.key      -- 密钥材料
// result.extra    -- 附加材料（如 nonce）
// result.strings  -- 字符串表示（UUID/MAC/IPv4/Base 系列）

// 解码端（仅需对应算法 feature）
let plain = malefic_codec::xor::decode(&result.encoded, &result.key, &result.extra);
assert_eq!(plain, payload);
```

```toml
# Cargo.toml 按需选择
[dependencies]
malefic-codec = { path = "../codec", features = ["encoder", "codec_xor", "codec_aes"] }
```

## 统一接口

每个算法模块均导出相同签名的函数：

```rust
// 编码（需 encoder feature）
fn encode(data: &[u8]) -> EncodeResult;

// 解码（始终可用）
fn decode(data: &[u8], key: &[u8], extra: &[u8]) -> Vec<u8>;
```
