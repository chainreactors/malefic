# malefic-scheduler

异步任务调度器，负责任务的派发、执行、生命周期管理与结果收集。

## 功能简介

- **任务调度 (`Scheduler`)**：通过异步事件循环接收任务请求，将模块封装为独立异步任务并发执行
- **任务管理 (`TaskManager`)**：维护活跃任务表，支持取消、查询、列举、完成等操作
- **结果收集 (`Collector`)**：汇聚所有任务产出的结果，按需批量返回给调用方
- **流式输入/输出**：每个任务拥有独立的输入/输出通道，支持运行中持续接收数据与发送结果
- **跨运行时支持**：通过 feature 切换底层异步运行时（tokio / async-std / smol）

## 核心概念

### Scheduler

调度器主循环通过 `futures::select!` 同时监听三类事件：

1. **任务提交** — 新模块到达时创建异步任务；已存在的任务 ID 则向其输入通道追加数据
2. **任务结果** — 将完成的结果通过数据通道转发给 Collector
3. **控制指令** — 处理 `TaskOperator`（取消、查询、列举、完成）

### TaskOperator

```rust
pub enum TaskOperator {
    CancelTask(u32),   // 取消指定任务
    FinishTask(u32),   // 标记任务完成并清理
    QueryTask(u32),    // 查询单个任务状态
    ListTask,          // 列举所有活跃任务
}
```

### Collector

结果收集器在独立协程中运行，持续接收各任务的输出，并在收到请求信号时将已缓存的结果批量打包返回。

#### 内存加密存储

Collector 对缓存的任务结果实施内存加密保护：

- **存储时加密**：收到 `Spite` 后，先通过 prost 序列化为字节，再使用 `Cryptor` 加密后存入缓冲区
- **发送时解密**：调用 `get_spites()` 时，逐条解密并反序列化还原为 `Spite`，随后清空缓冲区并重置加密器
- **密钥管理**：每个 Collector 实例在初始化时生成独立的随机密钥（32 字节 key + 16 字节 iv），密钥仅存在于进程内存中
- **加密算法**：由 YAML 配置文件中 `basic.encryption` 字段决定，支持 `aes`（AES-256-CTR，默认）、`xor`、`chacha20`，通过编译时 feature 自动选择

```
数据流：
  收集: Spite → encode_to_vec() → cryptor.encrypt() → Vec<Vec<u8>> (密文缓冲)
  发送: Vec<Vec<u8>> → cryptor.decrypt() → Spite::decode() → Spites (明文批量返回)
```

## Features

| Feature | 说明 |
|-----------|------|
| `tokio` | 使用 tokio 作为异步运行时（默认启用） |
| `async-std` | 使用 async-std 作为异步运行时 |
| `smol` | 使用 smol 作为异步运行时 |

## 基本用法

```rust
use futures::channel::mpsc;
use malefic_scheduler::{Scheduler, Cronner};
use malefic_scheduler::collector::Collector;

// 创建通道
let (response_sender, mut response_receiver) = mpsc::unbounded();
let mut collector = Collector::new(response_sender);

// 初始化调度器，将数据通道连接到 Collector
let mut scheduler = Scheduler::new(collector.get_data_sender());

// 获取任务提交通道与控制通道
let task_sender = scheduler.get_task_sender();
let ctrl_sender = scheduler.get_task_ctrl_sender();

// 在独立协程中运行调度器与收集器
spawn(async move { scheduler.run().await });
spawn(async move { collector.run().await });

// 通过 task_sender 提交任务
// task_sender.send((is_async, task_id, module, body)).await;
```

## 架构概览

```
任务提交 ──> Scheduler ──> spawn 异步任务
                │                  │
          控制指令(取消/查询)    任务结果
                │                  │
                v                  v
          TaskManager          Collector ──> 批量返回结果
                              (内存加密存储)
```

## 参考链接

- [futures crate](https://docs.rs/futures)
- [tokio](https://docs.rs/tokio)
- [async-std](https://docs.rs/async-std)
- [smol](https://docs.rs/smol)
