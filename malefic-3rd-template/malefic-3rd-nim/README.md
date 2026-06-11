# malefic-3rd-nim

Nim 语言模块，通过 `{.importc.}` pragma 导入 nanopb C 函数，编译为静态库后链接。

## 前置要求

- [Nim](https://nim-lang.org/install.html) 2.0+（需在 PATH 中）
- MinGW-w64 GCC（Nim 的 `--cc:gcc` 后端）

## 目录结构

```
malefic-3rd-nim/
├── Cargo.toml
├── build.rs                    # cc 编译 nanopb + nim c --app:staticlib
└── src/
    ├── lib.rs                  # Rust 侧 FFI 桥接 (含 NimMain 初始化)
    └── nim/
        ├── nanopb/             # nanopb 源码
        ├── malefic/            # protobuf 生成文件 (module.pb.c/h)
        └── example/
            └── example.nim     # 示例模块
```

## 构建流程

`build.rs` 自动完成以下步骤：

1. `cc` crate 编译 nanopb core + `module.pb.c` → 静态库
2. `nim c --app:staticlib --mm:arc --noMain:on` 编译 `.nim` → `.a`
3. 链接两个静态库

## 编写模块

```nim
{.passC: "-DPB_FIELD_32BIT".}

# 导入 nanopb 类型
type
  malefic_Request {.importc, header: "module.pb.h".} = object
    name: array[256, char]
    input: array[256, char]
  malefic_Response {.importc, header: "module.pb.h".} = object
    output: array[4096, char]
    error: array[256, char]

# nanopb field descriptors（C 数组衰减为指针）
var malefic_Request_fields_ptr {.importc: "malefic_Request_fields",
    header: "module.pb.h".}: ptr byte
var malefic_Response_fields_ptr {.importc: "malefic_Response_fields",
    header: "module.pb.h".}: ptr byte

# nanopb 函数
proc pb_istream_from_buffer(buf: ptr uint8, bufsize: csize_t):
    pb_istream_t {.importc, header: "pb_decode.h".}
proc pb_decode(stream: ptr pb_istream_t, fields: ptr byte,
    dest: pointer): bool {.importc, header: "pb_decode.h".}
# ... pb_encode 类似

const MODULE_NAME: cstring = "your_module"

proc NimModuleName(): cstring {.exportc, cdecl.} =
  return MODULE_NAME

proc NimModuleHandle(task_id: uint32, req_data: cstring, req_len: cint,
                     resp_data: ptr cstring, resp_len: ptr cint):
                     cint {.exportc, cdecl.} =
  # 1. memset 零初始化（不能用 _init_zero 宏）
  # 2. pb_decode 解码 Request
  # 3. 构造 Response
  # 4. pb_encode 编码
  # 5. malloc 输出 buffer（Rust 侧 free）
  return 0
```

### 要点

- 使用 `c_memset` 零初始化结构体，不能使用 nanopb 的 `_init_zero` 宏（C compound literal 在 Nim 生成的 C 代码中不兼容）
- `malefic_Request_fields` 声明为 `ptr byte` 直接使用，不需要取地址
- 使用 `{.exportc, cdecl.}` 导出 C ABI 符号
- 使用 `c_malloc` / `c_free`（映射到 C stdlib）分配内存
- Nim 运行时需要初始化：Rust 侧通过 `std::sync::Once` 调用 `NimMain()` 一次
- 编译使用 `--mm:arc`（不要用已废弃的 `--gc:arc`）

## 构建

```bash
cargo build --target x86_64-pc-windows-gnu --no-default-features \
  --features "as_cdylib,nim_module" --release
```
