# malefic-3rd-rust

Rust 语言模块，直接使用 `malefic-proto` 和 `malefic-trait` 提供的 trait 和宏。

## 前置要求

- Rust toolchain（与 workspace 一致）

## 目录结构

```
malefic-3rd-rust/
├── Cargo.toml
└── src/
    └── lib.rs          # 模块实现
```

## 编写模块

```rust
use async_trait::async_trait;
use malefic_trait::module_impl;
use malefic_proto::prelude::*;

pub struct YourModule {}

#[async_trait]
#[module_impl("your_module")]    // 模块名，用于注册和调度
impl Module for YourModule {}

#[async_trait]
impl ModuleImpl for YourModule {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut Input,
        sender: &mut Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;
        let response = Response {
            output: format!("hello, input: {}", request.input),
            ..Default::default()
        };
        Ok(TaskResult::new_with_body(id, Body::Response(response)))
    }
}

pub fn register(map: &mut MaleficBundle) {
    let module = YourModule::new();
    map.insert(<YourModule as Module>::name().to_string(), Box::new(module));
}
```

`#[module_impl("your_module")]` 宏会自动生成 `Module` trait 的 `name()` / `new()` / `new_instance()` 方法。

## 构建

```bash
cargo build --target x86_64-pc-windows-gnu --no-default-features \
  --features "as_cdylib,rust_module" --release
```
