# Rust 调用示例

通过 Rust 调用 WinKit 高级 API（RunPE、BOF、Reflective DLL 等）。

## 运行

```bash
cargo run --release
```

## 自定义

传递参数：
```rust
let args = b"--help";
// 在调用中传递 args
```

注入到进程：
```rust
let pid: u32 = 1234;
// 在调用中传递 pid
```

**详细说明见代码注释。**
