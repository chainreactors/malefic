use std::fs::File;
use std::io::{BufRead, BufReader, Error};
use std::path::{Path, PathBuf};

use super::socket::{
    format_ip, parse_hex_ip_v4, parse_hex_ip_v6, tcp_state_to_string, Protocol, Socket,
};

pub struct ProcReader {
    protocol: Protocol,
    path: PathBuf,
}

impl ProcReader {
    pub fn new<P: AsRef<Path>>(protocol: Protocol, path: P) -> Self {
        ProcReader {
            protocol,
            path: path.as_ref().to_owned(),
        }
    }

    pub fn read_sockets(&self) -> Result<Vec<Socket>, Error> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut sockets = Vec::new();

        // Skip header line
        for line in reader.lines().skip(1) {
            let line = line?;
            if let Some(socket) = self.parse_line(&line) {
                sockets.push(socket);
            }
        }

        Ok(sockets)
    }

    fn parse_line(&self, line: &str) -> Option<Socket> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 7 {
            return None;
        }

        match self.protocol {
            Protocol::Unix => self.parse_unix_line(&fields),
            _ => self.parse_inet_line(&fields),
        }
    }

    fn parse_unix_line(&self, fields: &[&str]) -> Option<Socket> {
        let inode = fields[6].parse::<u64>().ok()?;
        let path = if fields.len() >= 8 { fields[7] } else { "" };
        let type_and_state = u32::from_str_radix(fields[4], 16).ok()?;
        let socket_type = type_and_state & 0xf;
        let flags = u32::from_str_radix(fields[5], 16).ok()?;

        // 根据 /proc/net/unix 的格式，flags 字段的含义：
        // 0x00000000: 未连接
        // 0x00000001: 已连接
        // 0x00000010: 正在监听
        let state = match socket_type {
            1 => {
                // SOCK_STREAM
                if flags & 0x10 != 0 {
                    // ACC flag (SO_ACCEPTCON)
                    "LISTEN".to_string()
                } else if flags & 0x01 != 0 {
                    // CONNECTED flag
                    "ESTABLISHED".to_string()
                } else if flags & 0x02 != 0 {
                    // W_DISCONNECT
                    "CLOSING".to_string()
                } else if flags & 0x04 != 0 {
                    // R_DISCONNECT
                    "LAST_ACK".to_string()
                } else {
                    "DISCONNECTED".to_string()
                }
            }
            2 => "DGRAM".to_string(), // SOCK_DGRAM
            5 => {
                // SOCK_SEQPACKET
                if flags & 0x10 != 0 {
                    // ACC flag (SO_ACCEPTCON)
                    "LISTEN".to_string()
                } else if flags & 0x01 != 0 {
                    // CONNECTED flag
                    "ESTABLISHED".to_string()
                } else if flags & 0x02 != 0 {
                    // W_DISCONNECT
                    "CLOSING".to_string()
                } else if flags & 0x04 != 0 {
                    // R_DISCONNECT
                    "LAST_ACK".to_string()
                } else {
                    "DISCONNECTED".to_string()
                }
            }
            _ => "UNKNOWN".to_string(),
        };

        Some(Socket {
            local_addr: path.to_string(),
            remote_addr: String::new(),
            protocol: self.protocol.as_str().to_string(),
            pid: find_process_by_inode(inode).unwrap_or(0),
            state,
        })
    }

    fn parse_inet_line(&self, fields: &[&str]) -> Option<Socket> {
        if fields.len() < 12 {
            return None;
        }

        let (local_addr, remote_addr) = match self.protocol {
            Protocol::Tcp | Protocol::Udp => {
                let local = parse_hex_ip_v4(fields[1])?;
                let remote = parse_hex_ip_v4(fields[2])?;
                (
                    format_ip(local.0.into(), local.1),
                    format_ip(remote.0.into(), remote.1),
                )
            }
            Protocol::Tcp6 | Protocol::Udp6 => {
                let local = parse_hex_ip_v6(fields[1])?;
                let remote = parse_hex_ip_v6(fields[2])?;
                (
                    format_ip(local.0.into(), local.1),
                    format_ip(remote.0.into(), remote.1),
                )
            }
            Protocol::Unix => unreachable!(),
        };

        let state = match self.protocol {
            Protocol::Tcp | Protocol::Tcp6 => {
                let state_num = u8::from_str_radix(fields[3], 16).ok()?;
                tcp_state_to_string(state_num)
            }
            _ => String::new(),
        };

        let inode = fields[9].parse::<u64>().ok()?;
        let pid = find_process_by_inode(inode).unwrap_or(0);

        Some(Socket {
            local_addr,
            remote_addr,
            protocol: self.protocol.as_str().to_string(),
            pid,
            state,
        })
    }
}

pub fn find_process_by_inode(inode: u64) -> Option<u32> {
    // 首先检查所有进程的文件描述符
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // 检查是否是数字（PID）目录
            if let Some(pid_str) = path.file_name() {
                if let Some(pid_str) = pid_str.to_str() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        // 检查进程的文件描述符
                        let fd_dir = path.join("fd");
                        if let Ok(fd_entries) = std::fs::read_dir(fd_dir) {
                            for fd_entry in fd_entries.filter_map(Result::ok) {
                                if let Ok(target) = fd_entry.path().read_link() {
                                    if let Some(target_str) = target.to_str() {
                                        if target_str.contains(&format!("socket:[{}]", inode)) {
                                            return Some(pid);
                                        }
                                    }
                                }
                            }
                        }

                        // 检查线程的文件描述符
                        let task_dir = path.join("task");
                        if let Ok(task_entries) = std::fs::read_dir(task_dir) {
                            for task_entry in task_entries.filter_map(Result::ok) {
                                let fd_dir = task_entry.path().join("fd");
                                if let Ok(fd_entries) = std::fs::read_dir(fd_dir) {
                                    for fd_entry in fd_entries.filter_map(Result::ok) {
                                        if let Ok(target) = fd_entry.path().read_link() {
                                            if let Some(target_str) = target.to_str() {
                                                if target_str
                                                    .contains(&format!("socket:[{}]", inode))
                                                {
                                                    return Some(pid);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 如果没有找到,尝试从 /proc/net/tcp 和 /proc/net/udp 中查找
    for file in &[
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
    ] {
        if let Ok(content) = std::fs::read_to_string(file) {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 10 {
                    if let Ok(socket_inode) = fields[9].parse::<u64>() {
                        if socket_inode == inode {
                            // 找到匹配的 inode,现在尝试通过 uid 找到对应的进程
                            if let Ok(uid) = fields[7].parse::<u32>() {
                                return find_pid_by_uid(uid);
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

fn find_pid_by_uid(uid: u32) -> Option<u32> {
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            if let Some(pid_str) = path.file_name() {
                if let Some(pid_str) = pid_str.to_str() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        if let Ok(status) = std::fs::read_to_string(path.join("status")) {
                            if status.lines().any(|line| {
                                line.starts_with("Uid:")
                                    && line.split_whitespace().nth(1).map_or(false, |real_uid| {
                                        real_uid
                                            .parse::<u32>()
                                            .map_or(false, |uid_val| uid_val == uid)
                                    })
                            }) {
                                return Some(pid);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn read_proc_net_file<P: AsRef<Path>>(
    protocol: Protocol,
    path: P,
) -> Result<Vec<Socket>, Error> {
    let reader = ProcReader::new(protocol, path);
    reader.read_sockets()
}
