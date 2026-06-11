# malefic-3rd-zig

Zig 语言模块，通过 `@cImport` 直接导入 nanopb C 头文件，无需手写绑定。

## 前置要求

- [Zig](https://ziglang.org/download/) 0.13+（需在 PATH 中）

## 目录结构

```
malefic-3rd-zig/
├── Cargo.toml
├── build.rs                    # cc 编译 nanopb + zig build-obj
└── src/
    ├── lib.rs                  # Rust 侧 FFI 桥接
    └── zig/
        ├── nanopb/             # nanopb 源码
        ├── malefic/            # protobuf 生成文件 (module.pb.c/h)
        └── example/
            └── example.zig     # 示例模块
```

## 构建流程

`build.rs` 自动完成以下步骤：

1. `cc` crate 编译 nanopb core + `module.pb.c` → 静态库
2. `zig build-obj` 编译 `.zig` → `.obj`（带 `-lc` 链接 libc）
3. `cc` crate 将 zig object 包装为静态库，确保符号跨 crate 传播

## 编写模块

Zig 通过 `@cImport` 直接使用 nanopb 的 C 类型和函数：

```zig
const std = @import("std");
const c = @cImport({
    @cDefine("PB_FIELD_32BIT", {});
    @cInclude("pb_encode.h");
    @cInclude("pb_decode.h");
    @cInclude("module.pb.h");
});

const MODULE_NAME: [*:0]const u8 = "your_module";

export fn ZigModuleName() callconv(.C) [*:0]const u8 {
    return MODULE_NAME;
}

export fn ZigModuleHandle(
    task_id: u32,
    req_data: [*]const u8,
    req_len: c_int,
    resp_data: *[*]u8,
    resp_len: *c_int,
) callconv(.C) c_int {
    _ = task_id;

    // 解码 Request
    var request: c.malefic_Request = std.mem.zeroes(c.malefic_Request);
    var istream = c.pb_istream_from_buffer(req_data, @intCast(@as(usize, @intCast(req_len))));
    if (!c.pb_decode(&istream, c.malefic_Request_fields, &request))
        return -1;

    // 构造 Response
    var response: c.malefic_Response = std.mem.zeroes(c.malefic_Response);
    // ... 填充 response.output ...

    // 编码 Response
    var tmp_buf: [4096]u8 = undefined;
    var ostream = c.pb_ostream_from_buffer(&tmp_buf, tmp_buf.len);
    if (!c.pb_encode(&ostream, c.malefic_Response_fields, &response))
        return -1;

    // malloc 输出 buffer（Rust 侧 free）
    const encoded_len = ostream.bytes_written;
    const out_ptr: ?[*]u8 = @ptrCast(std.c.malloc(encoded_len) orelse return -1);
    @memcpy(out_ptr.?[0..encoded_len], tmp_buf[0..encoded_len]);
    resp_data.* = out_ptr.?;
    resp_len.* = @intCast(encoded_len);
    return 0;
}
```

### 要点

- 使用 `std.mem.zeroes()` 零初始化 nanopb 结构体
- 使用 `std.c.malloc` / `std.c.free` 分配内存（与 C 兼容）
- `@cImport` 自动将 C 类型映射为 Zig 类型，`pb_decode` 返回 `bool`
- `malefic_Request_fields` 已经是指针，不需要取地址

### 添加新 zig 文件

在 `build.rs` 中修改 zig 编译命令的源文件路径即可。

## 构建

```bash
cargo build --target x86_64-pc-windows-gnu --no-default-features \
  --features "as_cdylib,zig_module" --release
```
