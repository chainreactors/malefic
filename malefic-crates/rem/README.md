# malefic-rem

REM 远程执行引擎的 Rust FFI 封装，提供安全的内存通道读写与连接管理接口。

## 功能简介

- 通过 FFI 调用 REM 引擎的 C 接口（`RemDial`、`MemoryDial` 等）
- 提供 Rust 安全封装，将 C 风格错误码转换为 `Result` 类型
- 支持基于内存句柄的双向数据通道（读/写/关闭）
- 支持静态链接模式，在编译期绑定 REM 函数符号
- 统一的错误处理，覆盖命令解析、参数解析、连接失败等场景

## Features

| Feature | 说明 |
|---------|------|
| `rem` | 基础 feature，启用 REM FFI 声明 |
| `rem_static` | 默认启用，使用静态链接方式绑定 REM 函数 |

## 核心接口

| 函数 | 签名 | 说明 |
|------|------|------|
| `rem_dial` | `fn(cmdline: &str) -> Result<String, String>` | 发起 REM 连接，返回 Agent ID |
| `memory_dial` | `fn(memhandle: &str, dst: &str) -> Result<i32, String>` | 建立内存通道，返回句柄 |
| `memory_read` | `fn(handle: i32, buf: &mut [u8]) -> Result<usize, String>` | 从内存通道读取数据 |
| `memory_write` | `fn(handle: i32, buf: &[u8]) -> Result<usize, String>` | 向内存通道写入数据 |
| `memory_close` | `fn(handle: i32) -> Result<(), String>` | 关闭内存通道 |
| `cleanup` | `fn()` | 清理 Agent 资源 |

## 错误码

| 错误码 | 含义 |
|--------|------|
| `1` | 命令行解析失败 |
| `2` | 参数解析失败 |
| `3` | 准备阶段失败 |
| `4` | 缺少 Console URL |
| `5` | 创建 Console 失败 |
| `6` | 连接失败 |

## 基本用法

```rust
use malefic_rem::{rem_dial, memory_dial, memory_read, memory_write, memory_close, cleanup};

// 1. 发起 REM 连接
let agent_id = rem_dial("--server 10.0.0.1:8443")?;

// 2. 建立内存通道
let handle = memory_dial(&agent_id, "target_endpoint")?;

// 3. 写入数据
let written = memory_write(handle, b"hello")?;

// 4. 读取响应
let mut buf = vec![0u8; 4096];
let n = memory_read(handle, &mut buf)?;

// 5. 关闭通道并清理
memory_close(handle)?;
cleanup();
```

## 架构说明

该 crate 通过 `RemApi` trait 抽象 REM 函数的加载方式：

- **`RemStatic`**（`rem_static` feature）：编译期静态链接，直接引用外部 C 符号
- 函数指针存储在 `RemFunctions` 结构体中，运行时通过单例模式懒加载

## 参考链接

- [Rust FFI 指南](https://doc.rust-lang.org/nomicon/ffi.html)
