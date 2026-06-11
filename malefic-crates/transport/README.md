# malefic-transport

多协议异步网络传输层，提供 TCP、HTTP、REM 等传输协议的统一抽象接口。

## 功能简介

- **多协议支持**：通过 feature 切换 TCP / HTTP / REM 传输后端，编译期选择，零运行时开销
- **TLS / mTLS**：基于 rustls 实现 TLS 1.2/1.3 加密传输，支持自签名证书和双向认证（mTLS）
- **代理支持**：内置 HTTP CONNECT 和 SOCKS5 代理客户端，支持配置、环境变量和编译期三种代理源
- **加密会话**：Session 层集成对称加密，自动完成数据的分帧、加解密和超时控制
- **连接管理**：ConnectionBuilder 模式构建连接，支持读写分离和 Heartbeat / Duplex 双工模式切换
- **服务端轮转**：ServerManager 支持多目标自动切换、失败重试和可选的 DGA 域名生成
- **反向绑定**：`bind` feature 启用 TCP 监听端，支持反向连接场景

## Features

| Feature | 说明 |
|---------|------|
| `transport_tcp` | TCP 传输后端（默认启用） |
| `transport_http` | HTTP 传输后端，基于 TCP 封装 HTTP 请求/响应 |
| `transport_rem` | REM 内存传输后端，通过共享内存通信 |
| `tcp` | 底层 TCP 连接能力 |
| `tls` | 启用 TLS 加密（rustls） |
| `mtls` | 启用双向 TLS 认证（依赖 `tls`） |
| `proxy` | 启用 HTTP / SOCKS5 代理支持 |
| `bind` | 启用 TCP 监听绑定（反向连接） |
| `dga` | 启用域名生成算法（DGA）自动生成目标地址 |
| `tokio` | 使用 tokio 异步运行时（默认启用） |
| `async-std` | 使用 async-std 异步运行时 |
| `smol` | 使用 smol 异步运行时 |

## 基本用法

```rust
use malefic_transport::{
    Client, ConnectionBuilder, ConnectionRunner, SessionConfig,
};
use malefic_transport::DialerExt;
use malefic_crypto::crypto::new_cryptor;
use std::time::Duration;

// 1. 创建传输客户端并连接
let mut client = Client::new()?;
let transport = client.connect(&server_config).await?;

// 2. 通过 Builder 构建加密连接
let connection = ConnectionBuilder::new(transport)
    .with_cryptor(new_cryptor(key, iv))
    .with_session_id([0x01, 0x02, 0x03, 0x04])
    .with_config(SessionConfig {
        read_chunk_size: 8 * 1024,
        deadline: Duration::from_secs(5),
    })
    .build()?;

// 3. 使用 ConnectionRunner 进行通信
let mut runner = ConnectionRunner::new(connection);

// Heartbeat 模式：阻塞式收发
runner.send(spites).await?;
let response = runner.receive().await?;

// 升级为 Duplex 模式：后台异步接收
runner.upgrade()?;
runner.send(spites).await?;
let msg = runner.try_receive()?; // 非阻塞接收

// 降级回 Heartbeat 模式
runner.downgrade().await?;
```

## 核心类型

| 类型 | 说明 |
|------|------|
| `Client` | 传输协议客户端，根据 feature 自动选择 TCP/HTTP/REM |
| `Session` | 加密会话，负责数据分帧、加解密和超时 |
| `Connection` | 高层连接，支持 exchange 和读写分离 |
| `ConnectionRunner` | 连接运行器，管理 Heartbeat / Duplex 模式切换 |
| `ServerManager` | 多服务端管理器，处理轮转、重试和 DGA |

## 参考链接

- [rustls](https://github.com/rustls/rustls) - Rust TLS 实现
- [async-tls](https://github.com/async-rs/async-tls) - 异步 TLS 封装
- [futures](https://github.com/rust-lang/futures-rs) - Rust 异步基础库
