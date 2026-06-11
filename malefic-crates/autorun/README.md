# malefic-autorun

加密任务加载与并发执行引擎，从预置或外部的二进制数据中解密、解压并反序列化任务列表，通过信号量控制并发度并行执行所有任务。

## 功能简介

- **加密任务加载**：使用 AES 对称加密保护任务数据（`spite.bin`），运行时自动解密并解压
- **多种数据来源**：支持编译时嵌入（含混淆加密）、编译时嵌入（明文）、运行时从外部文件读取三种模式
- **并发执行引擎**：基于 Tokio 多线程运行时，通过 `Semaphore` 控制最大并发数（默认 6）
- **模块化任务分发**：自动根据任务名称查找对应模块，创建独立实例执行，互不干扰
- **错误隔离**：每个任务在独立的 `tokio::spawn` 中运行，单个任务失败不影响其他任务

## Features

| Feature | 说明 |
|---------|------|
| `embed` | 使用混淆加密方式在编译时嵌入 `spite.bin`，增强静态分析对抗能力 |
| `external_spite` | 运行时从可执行文件同级目录或当前目录读取 `spite.bin` 文件 |
| _(default)_ | 使用 `include_bytes!` 在编译时直接嵌入 `spite.bin` |

**优先级**：`external_spite` > `embed` > 默认嵌入。当 `external_spite` 启用时，忽略嵌入方式。

## 基本用法

```rust
use malefic_autorun;

// 使用默认并发度（6）执行所有预置任务
malefic_autorun::run().unwrap();

// 自定义并发度
malefic_autorun::run_with_concurrency(10).unwrap();
```

### 执行流程

```text
spite.bin (加密数据)
    |
    v
AES 解密 (key 由 malefic-config 提供, iv = key 的逆序)
    |
    v
解压缩 (decompress)
    |
    v
Protobuf 反序列化 -> Vec<Spite>
    |
    v
Autorun::execute() -> 并发执行所有任务
    |
    v
Vec<Spite> (执行结果)
```

### Autorun 结构体

```rust
use malefic_autorun::Autorun;

// 创建执行引擎，指定最大并发数
let autorun = Autorun::new(4)?;

// 执行任务列表，返回所有任务的执行结果
let results = autorun.execute(tasks).await?;
```

## 配置说明

- **spite.bin**：任务数据文件，需放置在 `resources/spite.bin`（编译时嵌入）或可执行文件同级目录（外部加载）
- **加密密钥**：由 `malefic-config::KEY` 提供，IV 为密钥的逆序排列

## 参考链接

- [Tokio - 异步运行时](https://tokio.rs/)
- [Protocol Buffers](https://protobuf.dev/)
