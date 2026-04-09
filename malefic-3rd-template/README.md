# Malefic 3rd Party Module Template

用于创建 malefic implant 第三方模块的模板项目，支持 **Rust / Go / C / Zig / Nim** 五种语言编写模块。

Malefic 本体采用最小化依赖设计，所有需要引入第三方库的 module 都在 3rd 中实现。官方维护的公开 3rd module 见 [malefic-3rd](https://github.com/chainreactors/malefic/tree/master/malefic-3rd)。

## 项目结构

```
malefic-3rd-template/
├── Cargo.toml                        # Workspace 根 + cdylib 入口
├── src/lib.rs                        # 模块注册入口 (rt_* C ABI 导出)
├── malefic-3rd-ffi/                  # 共享 FFI 工具库
│   └── src/lib.rs                    #   HandlerFn, ffi_handler_loop, RtModule re-exports
├── malefic-3rd-rust/                 # Rust 模块
├── malefic-3rd-go/                   # Go 模块 (双向流式 FFI)
├── malefic-3rd-c/                    # C 模块 (nanopb + 同步 handler)
├── malefic-3rd-zig/                  # Zig 模块 (nanopb + 同步 handler)
├── malefic-3rd-nim/                  # Nim 模块 (nanopb + 同步 handler)
└── tests/test_load_dll.rs            # 集成测试 (动态加载 DLL 验证)
```

## Runtime 协议

3rd-party 模块通过 `malefic-runtime` 的 **C ABI 协议**导出，解决了跨 Rust 版本/target 的 ABI 兼容性问题。

### DLL 导出（7 个 `extern "C"` 函数）

| 导出函数 | 签名 | 说明 |
|----------|------|------|
| `rt_abi_version` | `() -> u32` | 返回 ABI 版本号（当前为 2） |
| `rt_module_count` | `() -> u32` | 模块数量 |
| `rt_module_name` | `(index: u32) -> RtBuffer` | 第 i 个模块的名称 |
| `rt_module_create` | `(name, len) -> *mut Handle` | 创建模块实例 |
| `rt_module_destroy` | `(handle)` | 销毁模块实例 |
| `rt_module_run` | `(handle, task_id, ctx, send, recv, try_recv, free, out) -> Status` | 执行模块（阻塞） |
| `rt_free` | `(buf)` | 释放模块侧分配的 buffer |

### 数据链路

```
┌─────────────────── Implant (Host) ───────────────────┐
│                                                       │
│  Server Command → Scheduler → module.run(channel)     │
│       ↓                           ↓                   │
│  async Input ──→ input_forwarder ──→ std::sync::mpsc  │
│  channel          (encode Body       Sender ─────────────→ bridge_recv() ──→ ch.recv()
│                    → Spite bytes)                     │         ↓
│                                                       │    ┌─── Module DLL ──────────┐
│  async Output ←── output_forwarder ←── std::sync::mpsc│    │                         │
│  channel          (decode Spite        Receiver ←────────── bridge_send() ←── ch.send()
│                    → TaskResult)                      │    │                         │
│       ↓                                               │    │  RtModule::run(ch)      │
│  Collector → encrypt → send to Server                 │    │    ch.recv() → 处理     │
│                                                       │    │    ch.send() → 响应     │
│  每个 module 在独立的 spawn_blocking 线程中运行         │    │    return Done(body)    │
│  不阻塞主 async 运行时                                 │    └─────────────────────────┘
└───────────────────────────────────────────────────────┘
```

### 支持的数据流模式

| 模式 | 描述 | 示例 |
|------|------|------|
| **请求-响应** | recv 一次, return Done | pwd, cat |
| **流式上传** | recv 多次 (UploadRequest + Block×N), send 中间 ack | upload |
| **流式下载** | recv 请求, send 多次 chunk | download |
| **Module 持续推送** | 无需 input, 持续 send | keylogger, screen capture |
| **Host 持续推送** | 持续 recv, 最终 return 汇总 | 数据收集 |
| **双向持续** | 持续 recv + send 交替 | 交互式 shell |

### 内存所有权

| 方向 | 分配方 | 释放方 | 机制 |
|------|--------|--------|------|
| `ch.send()` (module→host) | Module | Module (回调返回后) | Host 在 bridge_send 内复制 |
| `ch.recv()` (host→module) | Host | Module 调 host_free | bridge_host_free 重建 Vec drop |
| `final_out` (module→host) | Module (RtBuffer::from_vec) | Host 调 rt_free | 各自 allocator 释放 |

**无跨 allocator 释放，纯 C ABI，跨 Rust 版本安全。**

## Feature 按需加载

通过 Cargo feature 控制编译哪些模块，未启用的模块不会编译进产物。

```toml
[features]
full = ["rust_module", "golang_module", "c_module", "zig_module", "nim_module"]

rust_module   = ["malefic-3rd-rust"]
golang_module = ["malefic-3rd-go"]
c_module      = ["malefic-3rd-c"]
zig_module    = ["malefic-3rd-zig"]
nim_module    = ["malefic-3rd-nim"]
```

### 选择性构建

```bash
# 全部模块
cargo build --target x86_64-pc-windows-gnu --release

# 只要 Rust + Go
cargo build --target x86_64-pc-windows-gnu --no-default-features \
  --features "as_cdylib,rust_module,golang_module" --release

# 只要 C + Zig
cargo build --target x86_64-pc-windows-gnu --no-default-features \
  --features "as_cdylib,c_module,zig_module" --release
```

## 外语 FFI 协议

所有非 Rust 语言模块遵循相同的 C ABI handler 协议：

| 导出函数 | 签名 | 说明 |
|----------|------|------|
| `XxxModuleName()` | `() -> *const char` | 返回模块名 |
| `XxxModuleHandle()` | `(task_id, req_data, req_len, &resp_data, &resp_len) -> int` | 同步处理请求 |

- 请求/响应使用 protobuf 序列化（C/Zig/Nim 用 nanopb，Go 用 protobuf-go）
- 响应 buffer 由模块侧 `malloc` 分配，Rust 侧通过 `free()` 释放
- Go 模块额外支持双向流式通信（Send/Recv/CloseInput）

外语 handler 通过 `ffi_handler_loop()` 桥接到 `RtModule::run()` 协议：

```
外语 handler 数据链路:

  RtChannel.recv()
    ↓ 解码 Body::Request
    ↓ encode_request() → protobuf bytes
    ↓ XxxModuleHandle(task_id, req_bytes) → resp_bytes
    ↓ decode_response(resp_bytes)
    ↓ 缓冲上一个结果
  RtChannel.send(上一个结果)  ← 中间响应
    ↓ 循环直到 EOF
  return Done(最后一个结果)    ← 最终响应
```

### Protobuf 协议（模块使用的核心消息）

```protobuf
message Request {
  string name = 1;
  string input = 2;
  repeated string args = 3;
  map<string, string> params = 4;
  bytes bin = 5;
}

message Response {
  string output = 1;
  string error = 2;
  map<string, string> kv = 3;
  repeated string array = 4;
}
```

## 添加新模块

### Rust 模块

```rust
// malefic-3rd-xxx/src/lib.rs
use malefic_3rd_ffi::*;

pub struct MyModule;

impl RtModule for MyModule {
    fn name() -> &'static str { "my_module" }
    fn new() -> Self { Self }

    fn run(&mut self, task_id: u32, ch: &RtChannel) -> RtResult {
        let body = ch.recv().map_err(|e| RtResult::Error(e.to_string()))?;
        // 处理...
        RtResult::Done(Body::Response(Response {
            output: "result".into(),
            ..Default::default()
        }))
    }
}
```

### C / Zig / Nim 模块

```rust
// malefic-3rd-xxx/src/lib.rs
use malefic_3rd_ffi::*;

extern "C" {
    fn XxxModuleName() -> *const c_char;
    fn XxxModuleHandle(task_id: c_uint, ...) -> c_int;
}

pub struct XxxModule { name: String }

impl RtModule for XxxModule {
    fn name() -> &'static str { "xxx_module" }
    fn new() -> Self {
        Self { name: unsafe { ffi_module_name(XxxModuleName, false) } }
    }
    fn run(&mut self, id: u32, ch: &RtChannel) -> RtResult {
        ffi_handler_loop(id, ch, XxxModuleHandle, "XxxModuleHandle")
    }
}
```

### 注册

1. 创建 `malefic-3rd-xxx/` crate
2. 根 `Cargo.toml` 添加 feature + optional dependency
3. `src/lib.rs` 的 `build_registry()` 中添加：

```rust
#[cfg(feature = "xxx_module")]
v.push(RtModuleDescriptor {
    name_fn: malefic_3rd_xxx::XxxModule::name,
    constructor: || Box::new(malefic_3rd_xxx::XxxModule::new()),
});
```

## 构建与测试

```bash
# 构建（全部模块）
cargo build --target x86_64-pc-windows-gnu --features full --release

# 测试
cargo test --target x86_64-pc-windows-gnu --features full -- --nocapture

# 加载到 implant
load_module --path target/x86_64-pc-windows-gnu/release/malefic_3rd.dll
```

## 跨版本兼容性

模块 DLL 可以用**不同的 Rust 版本**或**不同的 target（msvc/gnu）**编译，加载到用任意 Rust 版本编译的 host 中。已验证：

- rustc 1.81 / 1.82 / 1.93
- x86_64-pc-windows-msvc / x86_64-pc-windows-gnu
- msvc host 加载 gnu DLL，gnu host 加载 msvc DLL
