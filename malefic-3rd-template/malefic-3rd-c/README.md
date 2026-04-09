# malefic-3rd-c

C 语言模块，使用 [nanopb](https://github.com/nanopb/nanopb) 做 protobuf 序列化，`cc` crate 编译链接。

## 前置要求

- C 编译器（MinGW-w64 / GCC，随 Rust `x86_64-pc-windows-gnu` target 自带）

## 目录结构

```
malefic-3rd-c/
├── Cargo.toml
├── build.rs                    # cc crate 编译所有 C 源码
└── src/
    ├── lib.rs                  # Rust 侧 FFI 桥接
    └── c/
        ├── module.h            # FFI 接口声明
        ├── module.c            # FFI 导出 (CModuleName, CModuleHandle)
        ├── nanopb/             # nanopb 源码 (pb_encode/decode/common)
        ├── malefic/            # protobuf 生成文件 (module.pb.c/h, module.proto)
        └── example/
            └── example.c       # 示例模块
```

## 编写模块

实现 `module.h` 中声明的两个回调函数：

```c
#include "module.h"
#include "malefic/module.pb.h"
#include <pb_encode.h>
#include <pb_decode.h>

static const char MODULE_NAME[] = "your_module";

const char* module_name(void) {
    return MODULE_NAME;
}

static int your_handle(uint32_t task_id,
                       const char* req_data, int req_len,
                       char** resp_data, int* resp_len) {
    // 1. 解码 Request
    malefic_Request request = malefic_Request_init_zero;
    pb_istream_t istream = pb_istream_from_buffer(
        (const pb_byte_t*)req_data, (size_t)req_len);
    if (!pb_decode(&istream, malefic_Request_fields, &request))
        return -1;

    // 2. 构造 Response
    malefic_Response response = malefic_Response_init_zero;
    snprintf(response.output, sizeof(response.output),
             "hello from c, input: %s", request.input);

    // 3. 编码 Response
    uint8_t tmp[4096];
    pb_ostream_t ostream = pb_ostream_from_buffer(tmp, sizeof(tmp));
    if (!pb_encode(&ostream, malefic_Response_fields, &response))
        return -1;

    // 4. malloc 输出 buffer（Rust 侧 free）
    *resp_data = malloc(ostream.bytes_written);
    memcpy(*resp_data, tmp, ostream.bytes_written);
    *resp_len = (int)ostream.bytes_written;
    return 0;
}

module_handler_fn module_handler(void) {
    return your_handle;
}
```

然后在 `build.rs` 中添加你的 `.c` 文件：

```rust
cc::Build::new()
    // ...existing files...
    .file(c_src_dir.join("yourmod").join("yourmod.c"))
    .compile("malefic_c");
```

## 更新 protobuf

如果需要更新 proto 定义：

1. 编辑 `src/c/malefic/module.proto`
2. 用 nanopb generator 重新生成：
   ```bash
   nanopb_generator module.proto
   ```
3. 更新 `module.options` 中的字段大小限制

## 构建

```bash
cargo build --target x86_64-pc-windows-gnu --no-default-features \
  --features "as_cdylib,c_module" --release
```
