# malefic-sysinfo

跨平台系统信息收集库，提供统一的 API 获取操作系统、用户、网络及文件系统相关信息。

## 功能简介

- 获取操作系统名称、版本号、内核版本等基本信息
- 获取当前用户名、主机名、系统语言/区域设置
- 检测 CPU 架构（x86、x86_64、ARM、ARM64 等）
- 获取所有网络适配器的 IPv4 地址
- 查询当前主机所属域名（Active Directory 域）
- 检测当前进程是否具有管理员/root 权限
- 枚举磁盘驱动器及其类型（Windows）
- 文件系统工具：工作目录、可执行文件路径、SHA-256 校验和、文件查找
- 支持 Windows、Linux、macOS、Android 四个平台

## Features

| Feature | 说明 |
|---------|------|
| `clr` | 启用 .NET CLR 版本检测（仅 Windows），收集已安装的 .NET 运行时版本列表 |

## 核心数据结构

```rust
pub struct SysInfo {
    pub workdir: String,             // 当前工作目录
    pub filepath: String,            // 当前可执行文件路径
    pub os: Option<Os>,              // 操作系统信息（名称、版本、架构、用户名、主机名等）
    pub process: Option<Process>,    // 当前进程信息
    pub is_privilege: bool,          // 是否拥有管理员/root 权限
    pub ip_addresses: Vec<String>,   // 所有 IPv4 地址
    pub domain_name: String,         // 域名
}
```

## 基本用法

```rust
use malefic_sysinfo::{get_sysinfo, is_privilege};

// 一次性获取全部系统信息
let info = get_sysinfo();
println!("工作目录: {}", info.workdir);
println!("权限提升: {}", info.is_privilege);
println!("IP 地址: {:?}", info.ip_addresses);
println!("域名: {}", info.domain_name);

if let Some(os) = &info.os {
    println!("{} {} ({})", os.name, os.version, os.arch);
}

// 也可以单独调用各函数
let user = malefic_sysinfo::username();
let host = malefic_sysinfo::hostname();
let arch = malefic_sysinfo::arch();
```

### 文件系统工具

```rust
use malefic_sysinfo::filesys;

// 计算文件 SHA-256 校验和
let hash = filesys::check_sum("/path/to/file").unwrap();

// 在 PATH 中查找可执行文件
let path = filesys::lookup("notepad");

// 读取文件二进制内容
let (bytes, filename) = filesys::get_binary("target.exe").unwrap();
```

## 平台实现

| 模块 | Windows | Linux/Android | macOS |
|------|---------|---------------|-------|
| `whoami` | Win32 API + 注册表 | `/etc/os-release` + libc | sysctl + libc |
| `ipconfig` | `GetAdaptersAddresses` | 读取网络接口 | 读取网络接口 |
| `domain` | `DsGetDcNameW` (AD) | 解析配置文件 | 解析配置文件 |
| `driver` | `GetLogicalDriveStringsW` | — | — |

## 参考链接

- [Windows Win32 System Information API](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/)
- [Windows IP Helper API](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/)
- [Windows Active Directory API](https://learn.microsoft.com/en-us/windows/win32/api/dsgetdc/)
