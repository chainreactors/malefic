# malefic-guardrail

运行前环境验证与主机指纹检查，确保程序仅在符合预期的目标主机上执行。

## 功能简介

- 基于主机指纹进行环境校验，不匹配时立即终止进程
- 支持四类校验维度：IP 地址、用户名、主机名、域名
- 支持通配符模式匹配（`*` 匹配任意字符序列）
- 支持 `require_all` 严格模式（全部维度必须通过）与宽松模式（任一维度通过即可）
- 所有校验规则为空时自动跳过检查

## 校验维度

| 维度 | 配置字段 | 说明 |
|------|----------|------|
| IP 地址 | `ip_addresses` | 校验主机网络接口 IP 是否匹配 |
| 用户名 | `usernames` | 校验当前操作系统用户名是否匹配 |
| 主机名 | `server_names` | 校验主机 hostname 是否匹配 |
| 域名 | `domains` | 校验主机所属域名是否匹配 |

## 匹配规则

- 空字符串 `""` —— 仅匹配空值
- `"*"` —— 匹配任意值
- 不含 `*` 的字符串 —— 精确匹配
- 含 `*` 的字符串 —— 通配符匹配，`*` 转换为正则 `.*`

## 执行逻辑

每个维度独立计分（匹配得 1 分，满分 4 分）：

- **`require_all = true`**：四个维度全部通过（4 分）才放行
- **`require_all = false`**：任一维度通过（>0 分）即放行
- **校验失败**：调用 `std::process::exit(1)` 终止进程

若某个维度的配置列表为空，则该维度自动视为通过。

## 基本用法

```rust
use malefic_guardrail::Guardrail;
use malefic_sysinfo::SysInfo;

// 采集当前主机信息
let sysinfo = SysInfo::collect();

// 执行环境校验，不通过则进程退出
Guardrail::check(sysinfo);
```

## 配置示例

```yaml
guardrail:
  ip_addresses:
    - "192.168.1.*"
    - "10.0.0.100"
  usernames:
    - "admin"
  server_names:
    - "WORKSTATION-*"
  domains:
    - "corp.example.com"
  require_all: true
```

## 参考链接

- [regex crate](https://docs.rs/regex/latest/regex/) - Rust 正则表达式库
