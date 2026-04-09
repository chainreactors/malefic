# malefic-manager

模块与插件的生命周期管理器，负责模块注册、热加载、插件存储及任务调度等核心管理功能。

## 功能简介

- **模块管理**：统一注册、刷新和查询所有功能模块（`MaleficBundle`）
- **热加载**：运行时动态加载外部模块二进制，无需重启即可扩展能力
- **插件（Addon）管理**：加载、列举和执行自定义插件，插件内容自动压缩加密存储
- **内部指令**：内置 `ping`、`sleep`、`suicide`、`key_exchange` 等系统级内部模块枚举
- **多运行时支持**：通过 feature 选择 `tokio`、`async-std` 或 `smol` 异步运行时

## Features

| Feature | 说明 |
|---------|------|
| `tokio` | 使用 tokio 作为异步运行时（默认启用） |
| `async-std` | 使用 async-std 作为异步运行时 |
| `smol` | 使用 smol 作为异步运行时 |
| `hot_load` | 启用运行时热加载外部模块（默认启用） |
| `addon` | 启用插件管理功能（默认启用） |

## 核心结构

### `MaleficManager`

管理器主结构体，维护模块注册表（`bundles`）、已加载模块实例（`modules`）以及插件映射（`addons`）。

### `InternalModule`

内部模块枚举，定义了无需外部加载即可使用的系统级指令：

| 指令 | 说明 |
|------|------|
| `ping` / `keepalive` | 心跳与保活 |
| `init` | 初始化 |
| `load_module` / `refresh_module` / `list_module` | 模块热加载、刷新、列举 |
| `load_addon` / `list_addon` / `execute_addon` / `refresh_addon` | 插件加载、列举、执行、刷新 |
| `sleep` / `suicide` | 休眠与自毁 |
| `cancel_task` / `query_task` / `list_task` | 任务取消、查询、列举 |
| `key_exchange` / `switch` / `clear` | 密钥交换、切换、清理 |

### `AddonMap`

插件存储映射，插入时自动对内容进行压缩和加密，读取时自动解密和解压，保证插件内容在内存中的安全性。

## 基本用法

```rust
use malefic_manager::manager::MaleficManager;

// 创建管理器并显式注册应用层提供的 bundle
let mut manager = MaleficManager::new();
manager.register_bundle("origin", my_register_modules);
manager.refresh_module().unwrap();

// 列举当前所有可用模块
let internal = malefic_manager::internal::InternalModule::all();
let (all_modules, bundle_map) = manager.list_module(internal);

// 按名称获取模块
if let Some(module) = manager.get_module(&"module_name".to_string()) {
    // 使用 module ...
}
```

## 参考链接

- [strum - Rust 枚举字符串派生](https://crates.io/crates/strum)
- [tokio - Rust 异步运行时](https://crates.io/crates/tokio)
