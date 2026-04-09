# malefic-common

共享错误类型与异步运行时抽象，为上层模块提供统一的错误处理和运行时接口。

## 功能简介

- **统一错误类型**：定义 `MaleficError` 和 `CommonError` 两套错误枚举，覆盖任务调度、模块管理、传输层、IO 等场景
- **异步运行时抽象**：通过 feature gate 在 `async-std`、`tokio`、`smol` 三种运行时之间切换，对外暴露统一的 `spawn`、`spawn_blocking`、`Handle` 接口
- **可取消任务句柄**：提供 `CancellableHandle` trait 与 `RuntimeHandle` 类型，支持对异步任务的统一取消操作
- **底层工具函数**：指针算术、DJB2 字符串哈希、C/宽字符串长度计算、命令行格式化等实用工具
- **辅助宏**：`check_body!` 用于提取和校验消息体，`to_error!` 统一错误转换，`debug!` 条件编译调试输出

## Features

| Feature | 说明 |
|---------|------|
| `async-std` | 使用 async-std 作为异步运行时 |
| `tokio` | 使用 tokio 作为异步运行时 |
| `smol` | 使用 smol 作为异步运行时 |
| `register_info` | 启用注册信息相关功能 |

> 三个运行时 feature 互斥，构建时只能启用其中一个。

## 基本用法

### 异步任务派发

```rust
use malefic_common::{spawn, spawn_blocking, Handle};

// 派发异步任务
let handle: Handle<()> = spawn(async {
    // 异步逻辑
});

// 派发阻塞任务到专用线程
let result = spawn_blocking(|| {
    // 阻塞计算
});
```

### 取消任务

```rust
use malefic_common::{RuntimeHandle, CancellableHandle};
use std::sync::{Arc, Mutex};

let handle: RuntimeHandle = Arc::new(Mutex::new(None));
// ... 启动任务后存入 handle ...
handle.cancel(); // 统一取消接口，底层自动适配不同运行时
```

### 错误处理

```rust
use malefic_common::error::MaleficError;
use malefic_common::common_error::CommonError;

// MaleficError 提供数字 ID，便于序列化传输
let err = MaleficError::ModuleNotFound;
assert_eq!(err.id(), 5);
```

### 辅助宏

```rust
use malefic_common::{check_body, to_error, debug};

// 条件编译调试输出（仅 debug 构建生效）
debug!("current state: {:?}", state);

// 统一错误转换
let result = to_error!(some_fallible_call());
```

### 工具函数

```rust
use malefic_common::utils::dbj2_str_hash;

let hash = dbj2_str_hash(b"KERNEL32.DLL");
```

## 参考链接

- [thiserror - 派生宏错误类型](https://docs.rs/thiserror)
- [async-trait](https://docs.rs/async-trait)
- [tokio](https://docs.rs/tokio)
- [async-std](https://docs.rs/async-std)
- [smol](https://docs.rs/smol)
