# malefic-process

跨平台进程管理与枚举工具库，支持 Windows、Linux、macOS（含 Android）。

## 功能简介

- 枚举系统所有进程，获取 PID、PPID、进程名、路径、架构、所属用户及命令行参数
- 根据 PID 查询单个进程的详细信息
- 获取当前进程信息
- 终止指定 PID 的进程（`kill`）
- 同步 / 异步方式启动子进程，并捕获 stdout 与 stderr
- 检测文件是否被占用（`is_file_in_use`）
- 调用系统 Shell 执行文件（Windows 使用 `ShellExecuteW`，Unix 直接 `spawn`）

## 平台实现

| 平台 | 实现方式 |
|------|----------|
| Windows | ToolHelp32 快照枚举进程；`NtQueryInformationProcess` 获取命令行；`IsWow64Process` 判断架构；Token 查询获取所属用户 |
| Linux / Android | 读取 `/proc` 文件系统（`stat`、`status`、`exe`、`cmdline`）；解析 ELF 头判断 32/64 位 |
| macOS | `sysctl` + `KERN_PROC` 枚举进程；`proc_pidpath` 获取路径；`KERN_PROCARGS2` 读取命令行；`P_LP64` 标志判断架构 |

## 核心类型

```rust
pub struct Process {
    pub name: String,   // 进程名
    pub pid: u32,       // 进程 ID
    pub ppid: u32,      // 父进程 ID
    pub arch: String,   // 架构（x86 / x64 / arm / aarch64）
    pub owner: String,  // 所属用户
    pub path: String,   // 可执行文件路径
    pub args: String,   // 命令行参数
}
```

## 基本用法

```rust
use malefic_process::{get_processes, get_process, get_current_process, kill};

// 枚举所有进程
let processes = get_processes().unwrap();
for (pid, proc) in &processes {
    println!("[{}] {} - {}", pid, proc.name, proc.path);
}

// 查询单个进程
let proc = get_process(1234).unwrap();
println!("owner: {}, arch: {}", proc.owner, proc.arch);

// 获取当前进程
if let Some(current) = get_current_process() {
    println!("当前进程: {} (PID {})", current.name, current.pid);
}

// 终止进程
kill(1234).unwrap();
```

### 启动子进程

```rust
use malefic_process::{run_command, async_command};

// 同步启动
let child = run_command("/bin/ls".into(), vec!["-la".into()]).unwrap();

// 异步启动
let child = async_command("/bin/ls".into(), vec!["-la".into()]).unwrap();
```

### Shell 执行与文件占用检测

```rust
use malefic_process::exec::{shell_execute, is_file_in_use};

if !is_file_in_use("/path/to/file") {
    shell_execute("/path/to/file", "open").unwrap();
}
```

## 注意事项

- Windows 下 `run_command` 和 `async_command` 使用 `CREATE_NO_WINDOW`（`0x08000000`）标志，不会弹出控制台窗口
- 枚举进程时部分系统进程（如 PID 0）可能因权限不足而跳过
- Linux 通过读取 ELF magic 字节判断架构，进程已退出或无权限时返回 `unknown`

## 参考链接

- [Windows ToolHelp32 API](https://learn.microsoft.com/en-us/windows/win32/toolhelp/tool-help-functions)
- [Linux /proc 文件系统](https://man7.org/linux/man-pages/man5/proc.5.html)
- [macOS sysctl KERN_PROC](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/sysctl.3.html)
