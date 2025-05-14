use crate::{to_error, CommonError};
use crate::darwin::netstat::get_sockets;
use crate::darwin::netstat::socket::{ProtocolSocketInfo, Socket};
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "macos")]
use crate::darwin::netstat;
#[cfg(target_os = "linux")]
use crate::linux::netstat;
#[cfg(target_os = "windows")]
use crate::win::netstat;

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct NetInterface {
    pub index: u32,
    pub name: String,
    pub mac: String,
    pub ips: Vec<String>,
}

pub fn get_network_interfaces() -> Result<Vec<String>, Error> {
    // TODO: 实现获取网络接口信息
    Ok(Vec::new())
}

#[derive(Debug, Clone)]
pub struct Netstat {
    pub local_addr: String,
    pub remote_addr: String,
    pub protocol: String,
    pub pid: u32,
    pub state: String,
}

pub fn get_netstat() -> Result<Vec<Netstat>, Error> {
    let sockets = get_sockets(true, true, true, true)?;
    let netstats = sockets.into_iter().map(|socket| {
        match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => Netstat {
                local_addr: format!("{}:{}", tcp.local_addr, tcp.local_port),
                remote_addr: format!("{}:{}", tcp.remote_addr, tcp.remote_port),
                protocol: "tcp".to_string(),
                pid: socket.pid,
                state: tcp.state.as_str().to_string(),
            },
            ProtocolSocketInfo::Udp(udp) => Netstat {
                local_addr: format!("{}:{}", udp.local_addr, udp.local_port),
                remote_addr: String::new(),
                protocol: "udp".to_string(),
                pid: socket.pid,
                state: String::new(),
            },
        }
    }).collect();
    Ok(netstats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_netstat() {
        let result = get_netstat();
        assert!(result.is_ok(), "Should get netstat information");
        let netstats = result.unwrap();
        assert!(!netstats.is_empty(), "Should have some network connections");

        for netstat in netstats {
            assert!(
                !netstat.local_addr.is_empty(),
                "Local address should not be empty"
            );
            assert!(!netstat.protocol.is_empty(), "Protocol should not be empty");
        }
    }
}
