# malefic-config

运行时配置管理与二进制 patch 模块，负责配置的定义、序列化/反序列化，以及通过嵌入式 blob 实现编译后的配置热替换。

## 功能简介

- 定义完整的运行时配置结构体 `RuntimeConfig`，涵盖调度、通信、代理、DGA、Guardrail 等配置项
- 在二进制中嵌入固定长度（4096 字节）的 `CONFIG_BLOB_TEXT` 缓冲区，支持编译后通过外部工具原地 patch 配置
- 使用 XOR 加密 + Base64 编码保护嵌入的配置数据
- 通过 `lazy_static` 在首次访问时加载配置，优先读取 patch 后的 blob，无 patch 时回退到编译期默认值
- 支持多种传输协议配置：TCP、HTTP、REM
- 支持 TLS/mTLS、代理、DGA 域名生成、Guardrail 环境校验等高级特性

## Features

| Feature | 说明 |
|---------|------|
| `encoder` | 启用配置编码功能（`encode_runtime_config`），通常仅在构建工具侧使用，implant 本身不需要 |

## 配置结构

`RuntimeConfig` 包含以下配置域：

| 配置域 | 字段 | 说明 |
|--------|------|------|
| 调度 | `cron`, `jitter` | Cron 表达式与抖动系数 |
| 通信模式 | `keepalive` | 新会话启动后是否直接进入 Duplex keepalive |
| 容错 | `retry`, `max_cycles` | 重试次数与最大循环数 |
| 身份 | `name`, `key` | 实例名称与加密密钥 |
| 代理 | `proxy_*`, `use_env_proxy` | 代理服务器配置 |
| DGA | `dga_enable`, `dga_key`, `dga_interval_hours` | 域名生成算法配置 |
| Guardrail | `guardrail` | 运行环境校验（IP、用户名、主机名、域） |
| 服务端 | `server_configs` | 多服务端连接配置列表 |

## 基本用法

直接通过导出的静态变量访问配置：

```rust
use malefic_config::{CRON, KEEPALIVE, KEY, SERVER_CONFIGS, RUNTIME_CONFIG};

// 访问调度配置
let cron_expr = CRON.as_str();
let jitter = *malefic_config::JITTER;
let keepalive = *KEEPALIVE;

// 访问服务端配置
for server in SERVER_CONFIGS.iter() {
    println!("address: {}, protocol: {:?}", server.address, server.protocol);
}
```

编码配置（需启用 `encoder` feature，用于构建工具侧）：

```rust
use malefic_config::{encode_runtime_config, decode_runtime_config_str, RuntimeConfig};

// 将 RuntimeConfig 编码为固定长度的 4096 字节字符串
let encoded = encode_runtime_config(&config).expect("encode failed");

// 解码还原
let decoded = decode_runtime_config_str(&encoded).expect("decode failed");
```

## Blob Patch 原理

1. 编译时，`CONFIG_BLOB_TEXT` 以 `#[no_mangle]` 导出一个 4096 字节的固定缓冲区（前缀 `CFGv3B64` + `#` 填充）
2. 外部 patch 工具在二进制中定位该缓冲区，将加密后的配置数据写入
3. 运行时 `load_runtime_config` 读取缓冲区，解密并反序列化为 `RuntimeConfig`
4. 若缓冲区未被 patch（全为填充字符），则使用编译期硬编码的默认配置

## 参考链接

- [Cron 表达式语法](https://docs.rs/cron/latest/cron/)
- [Domain Generation Algorithm (DGA)](https://en.wikipedia.org/wiki/Domain_generation_algorithm)
