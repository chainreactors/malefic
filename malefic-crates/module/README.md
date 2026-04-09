# malefic-module

定义模块统一 trait 接口、任务结果封装及辅助宏，为所有功能模块提供标准化的开发基础。

## 功能简介

- 定义 `Module` 和 `ModuleImpl` 异步 trait，规范模块的生命周期与执行入口
- 提供 `TaskResult` 结构体，统一封装任务执行结果、状态码与错误信息
- 提供 `TaskError` 错误枚举，覆盖字段校验、类型不匹配等常见错误场景
- 内置一组辅助宏（`check_request!`、`check_field!` 等），简化模块开发中的参数校验
- 通过 `prelude` 模块导出所有常用类型与宏，一行 `use` 即可开始开发

## 核心类型

| 类型 | 说明 |
|------|------|
| `Module` | 模块 trait，定义 `name()`、`new()`、`new_instance()` |
| `ModuleImpl` | 模块实现 trait，定义异步 `run()` 执行入口 |
| `TaskResult` | 任务执行结果，包含 `task_id`、`body`、`status` |
| `TaskError` | 任务错误枚举，每种变体对应唯一错误码 |
| `MaleficModule` | `dyn Module + Send + Sync + 'static` 的类型别名 |
| `MaleficBundle` | `HashMap<String, Box<MaleficModule>>`，模块注册表 |
| `Input` / `Output` | 基于 `futures-channel` 的异步输入/输出通道类型 |

## 辅助宏

| 宏 | 说明 |
|----|------|
| `check_request!` | 从输入通道接收消息并匹配预期变体，失败返回 `NotExpectBody` |
| `check_field!` | 校验字段非空或长度是否符合预期 |
| `check_optional!` | 校验 `Option` 字段是否为 `Some`，支持长度检查 |
| `register_module!` | 按 feature gate 将模块实例注册到 `MaleficBundle` |
| `to_error!` | 将任意错误转换为 `anyhow::Error` |
| `debug!` | 仅在 debug 构建时打印调试信息 |

## 基本用法

实现一个自定义模块：

```rust
use malefic_module::prelude::*;
use async_trait::async_trait;

pub struct MyModule;

#[async_trait]
impl Module for MyModule {
    fn name() -> &'static str { "my_module" }
    fn new() -> Self { MyModule }
    fn new_instance(&self) -> Box<MaleficModule> { Box::new(MyModule) }
}

#[async_trait]
impl ModuleImpl for MyModule {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut Input,
        sender: &mut Output,
    ) -> ModuleResult {
        // 从通道接收请求并校验
        let request = check_request!(receiver, Body::Request)?;
        let name = check_field!(request.name)?;

        // 构造返回结果
        Ok(TaskResult::new_with_body(id, Body::Response(Response {
            output: format!("hello {}", name),
            ..Default::default()
        })))
    }
}
```

注册模块到 bundle：

```rust
use malefic_module::prelude::*;

let mut bundle: MaleficBundle = HashMap::new();
register_module!(bundle, "my_module", MyModule);
```

## TaskError 错误码

| 错误码 | 变体 | 含义 |
|--------|------|------|
| 2 | `OperatorError` | 通用运行时错误 |
| 3 | `NotExpectBody` | 收到非预期的消息类型 |
| 4 | `FieldRequired` | 必填字段缺失 |
| 5 | `FieldLengthMismatch` | 字段长度不匹配 |
| 6 | `FieldInvalid` | 字段值无效 |
| 99 | `NotImpl` | 功能未实现 |
