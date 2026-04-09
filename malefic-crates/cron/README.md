# malefic-cron

轻量级 cron 调度器，基于标准 cron 表达式计算下次执行间隔，并支持 jitter 随机抖动。

## 功能简介

- 解析标准 cron 表达式（秒级精度，6 段格式）
- 计算当前时刻到下一次触发的毫秒间隔
- 支持 jitter 抖动，在基准间隔上叠加随机偏移，避免多实例同时触发
- 最小返回间隔 1000ms，防止过于频繁的调度
- 当无法获取下一次触发时间时，自动回退至 30 秒默认间隔

## 核心结构

### `Cronner`

| 字段 | 类型 | 说明 |
|------|------|------|
| `schedule` | `cron::Schedule` | 解析后的 cron 调度计划 |
| `jitter` | `f64` | 抖动系数，取值 `0.0`~`1.0`，`0.0` 表示无抖动 |

### 方法

| 方法 | 说明 |
|------|------|
| `new(expression, jitter)` | 根据 cron 表达式和 jitter 系数创建调度器 |
| `next_interval()` | 返回距下次触发的毫秒数（已含 jitter） |
| `expression()` | 返回原始 cron 表达式字符串 |

## 基本用法

```rust
use malefic_cron::Cronner;

// 每 30 秒触发一次，jitter 系数 0.1（即 +-10% 随机偏移）
let scheduler = Cronner::new("0/30 * * * * *", 0.1).unwrap();

// 获取下次执行的等待时间（毫秒）
let wait_ms = scheduler.next_interval();

// 工作时间段调度：每小时整点，9:00-17:00，无抖动
let work_scheduler = Cronner::new("0 0 9-17 * * *", 0.0).unwrap();
let interval = work_scheduler.next_interval();
```

## Jitter 机制

jitter 用于在基准间隔上引入随机偏移，计算方式：

```
jitter_range = base_ms * jitter
offset = random(-jitter_range, +jitter_range)
result = base_ms + offset
```

例如 `jitter = 0.2`、基准间隔 10000ms 时，实际间隔在 8000ms ~ 12000ms 之间随机分布。

## Cron 表达式格式

采用 6 段格式（含秒）：

```
秒 分 时 日 月 周
```

| 示例 | 含义 |
|------|------|
| `0/30 * * * * *` | 每 30 秒 |
| `0 */5 * * * *` | 每 5 分钟 |
| `0 0 9-17 * * *` | 每天 9:00-17:00 整点 |
| `0 0 0 * * MON-FRI` | 工作日零点 |

## 参考链接

- [cron crate](https://crates.io/crates/cron) - Rust cron 表达式解析库
- [Cron 表达式语法](https://en.wikipedia.org/wiki/Cron#CRON_expression)
