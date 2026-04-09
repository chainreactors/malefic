# Malefic Starship Launch Example

演示如何通过 `malefic-starship` 的 `launch` 模块加载和执行 shellcode。

## 编译

选择一个 loader feature 进行编译：

```bash
cargo build --features "func_ptr"
cargo build --features "basic_template"
```

可组合编码和规避 feature：

```bash
cargo build --features "func_ptr,enc_xor,evader_etw_pass"
```

## 运行

```bash
starship_example.exe <shellcode.bin> [target_pid]
```

## Launch API

| 函数 | 说明 |
|------|------|
| `launch::load_shellcode(path)` | 从文件加载 shellcode |
| `launch::decode_payload(data, key, extra)` | 使用编译时选定的编码器解码 |
| `launch::has_encoding()` | 检查是否启用了编码 feature |
| `launch::execute_loader(shellcode, pid)` | 使用编译时选定的 loader 执行 |
| `launch::run(data, key, extra, pid)` | 一站式 pipeline: 解码 → 规避 → 执行 |

## 可用 Loader Features

Community 版提供 2 种基础注入模板：

| Feature | 说明 |
|---------|------|
| `basic_template` | 空模板，用于自定义扩展 |
| `func_ptr` | 经典函数指针自注入 |

## 编码 Features

| Feature | 算法 |
|---------|------|
| `enc_xor` | XOR |
| `enc_uuid` | UUID encoding |
| `enc_mac` | MAC address encoding |
| `enc_ipv4` | IPv4 encoding |
| `enc_base64` | Base64 |
| `enc_aes` | AES |

## 规避 Features

| Feature | 说明 |
|---------|------|
| `evader_anti_emu` | 反模拟器检测 |
| `evader_etw_pass` | ETW bypass |
| `evader_god_speed` | God speed |
| `evader_sleep_encrypt` | Sleep 加密 |
| `evader_anti_forensic` | 反取证 |
| `evader_cfg_patch` | CFG patch |
| `evader_api_untangle` | API untangle |
| `evader_normal_api` | Normal API |
