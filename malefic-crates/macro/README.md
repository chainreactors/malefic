# malefic-macro

编译期代码混淆过程宏库，提供字符串加密、控制流平坦化、垃圾代码注入、结构体字段加密和文件嵌入加密等能力。所有混淆在编译期完成，运行时自动解密，各功能可通过 feature 独立开关。

## 功能简介

- **字符串/字节串加密** — 使用 AES-256-CTR 在编译期加密字面量，运行时解密
- **整数混淆** — 通过可逆运算链隐藏整数常量的真实值
- **控制流平坦化** — 将顺序语句转换为 loop/match 状态机（Goldberg 风格）
- **轻量控制流混淆** — 插入虚假循环与 `black_box` 干扰静态分析
- **垃圾代码注入** — 在函数体中自动插入无意义代码，增大逆向难度
- **结构体字段加密** — 派生宏生成 `Obfuscated<StructName>`，字段以 AES 加密存储
- **文件嵌入加密** — 编译期加密嵌入文件内容，运行时解密为 `Vec<u8>`
- **lazy_static 替代** — 基于 `OnceLock` 的 `lazy_static!`，自动对初始化表达式做字面量混淆
- **统一属性宏** — `#[obfuscate]` 一键启用字面量混淆、控制流平坦化和垃圾代码注入

## Features

| Feature | 说明 |
|---------|------|
| `literal_obf` | 启用字符串、字节串、整数字面量的 AES 加密混淆 |
| `control_flow` | 启用 `flow!` 和 `obf_stmts!` 控制流混淆 |
| `junk_insertion` | 启用 `#[junk]` 垃圾代码注入 |
| `struct_obf` | 启用 `#[derive(Obfuscate)]` 结构体字段加密 |
| `embed_encrypt` | 启用 `include_encrypted!` 文件嵌入加密 |

以上 feature 全部默认启用。关闭某个 feature 后，对应宏会退化为无混淆的直通实现。

## 基本用法

### 字符串与字节串加密

```rust
use malefic_macro::{obf_string, obfstr, obf_bytes};

let s: String = obf_string!("sensitive string");
let r: &'static str = obfstr!("also encrypted");
let b: Vec<u8> = obf_bytes!(b"raw bytes");
```

### 整数混淆

```rust
use malefic_macro::obf_int;

let key: u32 = obf_int!(0xDEADBEEF_u32);
```

### 控制流混淆

```rust
use malefic_macro::{flow, obf_stmts};

// 轻量混淆：插入虚假循环
flow! { do_something(); }

// Goldberg 状态机风格
obf_stmts! {
    step_one();
    step_two();
    step_three();
}
```

### 垃圾代码注入

```rust
use malefic_macro::junk;

#[junk(density = 3)]
fn my_function() {
    real_logic();
}
```

### 结构体字段加密

```rust
use malefic_macro::Obfuscate;

#[derive(Obfuscate)]
struct Config {
    api_key: String,
    secret: Vec<u8>,
}
```

### 文件嵌入加密

```rust
use malefic_macro::include_encrypted;

let data: Vec<u8> = include_encrypted!("path/to/payload.bin");
let data_aes: Vec<u8> = include_encrypted!(aes, "path/to/payload.bin");
```

### 统一属性宏

```rust
use malefic_macro::obfuscate;

#[obfuscate]                      // 仅字面量混淆
#[obfuscate(flow)]                // 字面量 + 控制流
#[obfuscate(junk = 2)]            // 字面量 + 垃圾注入
#[obfuscate(flow, junk = 2)]      // 全部启用
fn handler() { /* ... */ }
```

## 参考链接

- [AES crate](https://docs.rs/aes)
- [const-random](https://docs.rs/const-random) — 编译期随机数生成
- [syn](https://docs.rs/syn) — Rust 过程宏语法解析
