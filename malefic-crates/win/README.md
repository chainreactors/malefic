# malefic-os-win

Windows 平台专用工具集，封装了 Windows API 调用，提供令牌操作、注册表管理、管道通信、服务控制、计划任务、WMI 查询、反沙箱/反虚拟机检测、Sleep 混淆等功能。

## 功能简介

- **Token 操作** -- 获取/复制进程令牌、提权判断、权限启用、令牌模拟、`RunAs` 执行
- **注册表管理** -- 支持所有根键（HKLM/HKCU/...），提供键值的增删改查、子键枚举
- **管道通信** -- 命名管道（服务端/客户端）与匿名管道，用于进程间数据传输
- **服务管理** -- 创建、启动、停止、删除、查询 Windows 服务及批量枚举
- **计划任务** -- 通过 COM 接口操作 Task Scheduler，支持创建、运行、停止、删除、查询任务
- **WMI 查询** -- 连接 WMI 服务，执行 WQL 查询，支持方法调用与结果解析
- **反沙箱检测** -- 检查进程列表、注册表特征等指标判断是否运行在沙箱环境中
- **反虚拟机检测** -- 基于 CPUID 指令识别 VirtualBox/VMware/Hyper-V/QEMU/Xen 等虚拟化框架
- **Sleep 混淆** -- 在休眠期间加密内存区域，支持 Timer/Wait/Foliage 三种策略
- **函数 Hook** -- 基于 `detour` 库实现运行时 API Inline Hook
- **PE 加载** -- 反射式 PE 加载、InlinePE、RunPE 及牺牲进程执行
- **BOF 加载** -- 加载并执行 Beacon Object File
- **远程注入** -- 通过 CreateRemoteThread 向目标进程注入代码
- **Bypass** -- AMSI/ETW 等安全机制绕过（需启用 `bypass` feature）

## Features

| Feature | 说明 |
|----------------|------|
| `source` | 使用源码编译 `malefic-win-kit`（默认使用预编译库） |
| `prebuild` | 使用预编译的 `malefic-win-kit` 静态库 |
| `community` | 社区版功能集 |
| `professional` | 专业版功能集 |
| `detour` | 启用函数 Hook（Inline Hook）支持 |
| `bypass` | 启用 AMSI/ETW 绕过，隐含启用 `detour` |
| `token` | 启用令牌操作模块 |
| `reg` | 启用注册表操作模块 |
| `pipe` | 启用管道通信模块 |
| `scheduler` | 启用计划任务管理模块 |
| `service` | 启用服务管理模块 |
| `anti_sandbox` | 启用反沙箱检测 |
| `anti_vm` | 启用反虚拟机检测 |
| `clr` | 启用 CLR（.NET 运行时）加载 |
| `sleep_obf` | 启用 Sleep 混淆（休眠期间内存加密） |
| `wmi` | 启用 WMI 查询与方法调用 |

## 基本用法

### 令牌操作

```rust
use malefic_os_win::token;

// 判断当前进程是否具有管理员权限
let elevated = token::is_privilege()?;

// 启用指定权限
token::enable_privilege("SeDebugPrivilege")?;

// 模拟指定进程的令牌
let handle = token::impersonate_process(pid)?;
```

### 注册表读写

```rust
use malefic_os_win::reg::{RegistryHive, RegistryKey, RegistryValue};

let key = RegistryKey::open(RegistryHive::LocalMachine, r"SOFTWARE\MyApp")?;
let val = key.query_value("Version")?;
key.set_value("NewKey", RegistryValue::String("hello".into()))?;
```

### Sleep 混淆

```rust
use malefic_os_win::sleep::{obf_sleep, Obfuscation, ObfMode};

// 休眠 5 秒，期间使用 Timer 策略加密指定内存区域
obf_sleep(base_ptr, region_size, 5, Obfuscation::Timer, ObfMode::Heap);
```

## 参考链接

- [windows-rs](https://github.com/microsoft/windows-rs) -- Rust 官方 Windows API 绑定
- [retour-rs](https://github.com/chainreactors/retour-rs) -- Inline Hook 库（detour fork）
