# malefic-proto

Protobuf 协议定义与二进制传输序列化层，负责消息的编码、解码、封包与解包。

## 功能简介

- 基于 `prost` 从 `.proto` 文件自动生成 Rust 类型（`implantpb`、`modulepb`）
- 提供 `SpiteData` 传输帧结构：TLV 格式封包（起始标记 / Session ID / 长度 / 数据 / 结束标记）
- 内置数据压缩（通过 `malefic-crypto` 的 compress 模块）
- 可选加密支持：XOR、AES、ChaCha20 对称加密，以及 Age（X25519）非对称加密
- 提供心跳间隔抖动计算、会话 ID 生成等实用函数
- 统一的错误类型 `ParserError`，覆盖协议解析中的各类异常

## Features

| Feature | 说明 |
|---------|------|
| `crypto` | 启用加密基础依赖 |
| `crypto_xor` | XOR 对称加密 |
| `crypto_aes` | AES 对称加密（默认启用） |
| `crypto_chacha20` | ChaCha20 对称加密 |
| `secure` | 启用 Age (X25519) 非对称加密，用于端到端安全通信 |
| `enable_serde` | 为生成的 Protobuf 类型派生 `serde::Deserialize` |

## 传输帧格式

```text
+-------+------------+--------+------+-------+
| Start | Session ID | Length | Data |  End  |
| 0xd1  |  4 bytes   | u32 LE | ...  | 0xd2  |
+-------+------------+--------+------+-------+
```

Header 固定长度为 9 字节（1 + 4 + 4）。

## 基本用法

```rust
use malefic_proto::*;

// 创建一条 Spite 消息
let spite = new_spite(
    1,
    "my_task".to_string(),
    Body::Empty(implantpb::Empty {}),
);

// 序列化并封包
let session_id = get_sid();
let spites = Spites { spites: vec![spite] };
let frame = marshal(session_id, spites, None).unwrap();

// 打包为二进制传输数据
let wire_data = frame.pack();

// 接收端：解析 header
let mut received = parser_header(&wire_data[..HEADER_LEN]).unwrap();
// 填充 body 并解包
received.set_data(wire_data[HEADER_LEN..].to_vec()).unwrap();
let result = received.parse(None).unwrap();
```

### 使用 Age 加密

```rust
use malefic_proto::*;

// 生成密钥对（需启用 secure feature）
let (private_key, public_key) = generate_age_keypair();

// 加密封包
let frame = marshal(session_id, spites, Some(&public_key)).unwrap();

// 解密解包
let result = frame.parse(Some(&private_key)).unwrap();
```

## 核心 API

| 函数 | 说明 |
|------|------|
| `marshal` / `marshal_one` | 将 `Spites`/`Spite` 编码、压缩、加密后封装为 `SpiteData` |
| `encode` / `decode` | Protobuf 编码与解码 |
| `parser_header` | 从字节流解析传输帧头部 |
| `new_spite` / `new_empty_spite` / `new_error_spite` | 快速构建 `Spite` 消息 |
| `get_sid` | 生成随机 4 字节 Session ID |
| `new_heartbeat` | 计算带抖动的心跳间隔（毫秒） |

## 参考链接

- [prost - Protobuf for Rust](https://github.com/tokio-rs/prost)
- [Protocol Buffers](https://protobuf.dev/)
- [age encryption](https://github.com/FiloSottile/age)
