# malefic-net

跨平台网络连接枚举库，提供统一接口查询系统 Socket 连接与网络接口信息。

## 功能简介

- 枚举系统所有活跃的 TCP/UDP 连接（IPv4 + IPv6）
- 查询每条连接的本地/远程地址、协议类型、PID 及连接状态
- 查询网络接口信息（索引、名称、MAC 地址、IP 列表）
- 各平台使用原生 API 实现，无外部命令依赖

## 平台实现

| 平台 | 实现方式 | 支持的协议 |
|------|---------|-----------|
| Windows | `GetExtendedTcpTable` / `GetExtendedUdpTable` (Win32 API) | TCP, TCP6, UDP, UDP6 |
| Linux / Android | Netlink Socket（首选），`/proc/net/*` procfs（回退） | TCP, TCP6, UDP, UDP6, Unix |
| macOS | `sysctl` 内核接口 | TCP, TCP6, UDP, UDP6 |

## 核心数据结构

```rust
/// 网络连接信息
pub struct NetStat {
    pub local_addr: String,   // 本地地址 (ip:port)
    pub remote_addr: String,  // 远程地址 (ip:port)
    pub protocol: String,     // 协议: tcp / tcp6 / udp / udp6 / unix
    pub pid: String,          // 所属进程 PID
    pub sk_state: String,     // 连接状态: ESTABLISHED / LISTEN / ...
}

/// 网络接口信息
pub struct NetInterface {
    pub index: u32,           // 接口索引
    pub name: String,         // 接口名称
    pub mac: String,          // MAC 地址
    pub ips: Vec<String>,     // 绑定的 IP 地址列表
}
```

## 基本用法

```rust
use malefic_net::{get_netstat, get_network_interfaces};

// 枚举所有网络连接
let connections = get_netstat().unwrap();
for conn in &connections {
    println!("[{}] {} -> {} (pid={}, state={})",
        conn.protocol, conn.local_addr, conn.remote_addr,
        conn.pid, conn.sk_state);
}

// 查询网络接口
let interfaces = get_network_interfaces().unwrap();
for iface in &interfaces {
    println!("{}: mac={}, ips={:?}", iface.name, iface.mac, iface.ips);
}
```

底层 `get_sockets` 函数支持按协议过滤：

```rust
// 仅查询 IPv4 TCP 连接
let tcp_only = win::get_sockets(
    true,   // ipv4
    false,  // ipv6
    true,   // tcp
    false,  // udp
).unwrap();
```

## TCP 连接状态

返回的 `sk_state` 字段对应标准 TCP 状态机：

| 状态 | 说明 |
|------|------|
| `LISTEN` | 等待连接 |
| `ESTABLISHED` | 已建立连接 |
| `SYN_SENT` | 已发送 SYN |
| `SYN_RCVD` | 已收到 SYN |
| `FIN_WAIT1` | 主动关闭，等待 FIN-ACK |
| `FIN_WAIT2` | 已收到 ACK，等待 FIN |
| `TIME_WAIT` | 等待超时关闭 |
| `CLOSE_WAIT` | 被动关闭，等待应用关闭 |
| `CLOSING` | 双方同时关闭 |
| `LAST_ACK` | 等待最终 ACK |
| `CLOSED` | 已关闭 |

## 参考链接

- [GetExtendedTcpTable (Win32)](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
- [Linux Netlink SOCK_DIAG](https://man7.org/linux/man-pages/man7/sock_diag.7.html)
- [/proc/net/tcp 格式说明](https://www.kernel.org/doc/html/latest/networking/proc_net_tcp.html)
- [macOS sysctl 网络接口](https://developer.apple.com/documentation/kernel/sysctl)
