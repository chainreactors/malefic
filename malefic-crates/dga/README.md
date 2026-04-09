# malefic-dga

基于时间窗口和 SHA-256 哈希的域名生成算法（DGA）实现。

## 功能简介

- 根据当前时间窗口和预共享密钥，动态生成域名前缀
- 使用 SHA-256 对 `时间种子 + 密钥` 进行哈希，映射为 8 位小写字母前缀
- 支持可配置的时间窗口间隔（按小时划分）
- 自动将生成的域名应用到服务端配置（地址、TLS SNI、HTTP Host）
- 支持多域名后缀批量生成

## 核心结构

| 结构体 / 枚举 | 说明 |
|----------------|------|
| `TimeWindow` | 时间窗口，按年/月/日/小时段划分，用于生成种子字符串 |
| `DgaAlgorithm` | DGA 算法核心，持有密钥、间隔和域名后缀列表 |
| `DgaGenerator` | 高层生成器，从服务端配置模板生成新的带 DGA 域名的配置 |
| `DgaDomain` | 生成结果，包含完整域名、种子、前缀和后缀 |
| `DgaError` | 错误类型（禁用、无域名、无效时间窗口、生成失败） |

## 算法流程

1. 获取当前 UTC 时间，按配置的间隔小时数计算时间窗口
2. 拼接种子字符串：`{年}{月}{日}{小时段}{密钥}`
3. 对种子做 SHA-256 哈希，取前 8 字节映射到 `a-z`，得到域名前缀
4. 将前缀与每个域名后缀拼接，生成完整域名列表
5. 基于模板配置，更新地址、TLS SNI 和 HTTP Host 头

## 基本用法

```rust
use malefic_dga::{DgaAlgorithm, TimeWindow};

// 直接使用算法层
let algorithm = DgaAlgorithm::new(
    "my_secret_key".to_string(),
    12, // 每 12 小时切换一次域名
    vec!["example.com".to_string(), "example.org".to_string()],
);

let domains = algorithm.generate();
for d in &domains {
    println!("{}", d.domain); // e.g. "abcdefgh.example.com"
}
```

```rust
use malefic_dga::DgaGenerator;

// 从服务端配置模板生成
let generator = DgaGenerator::from_server_configs(server_configs)?;
let new_configs = generator.generate_new_server();
```

```rust
use malefic_dga::TimeWindow;

// 获取当前和前一个时间窗口
let current = TimeWindow::current(6);
let previous = current.previous(6);
println!("当前种子: {}", current.to_seed_string());
println!("上一窗口种子: {}", previous.to_seed_string());
```

## 参考链接

- [Domain Generation Algorithm - Wikipedia](https://en.wikipedia.org/wiki/Domain_generation_algorithm)
- [SHA-2 (sha2 crate)](https://docs.rs/sha2)
- [chrono - 日期时间库](https://docs.rs/chrono)
