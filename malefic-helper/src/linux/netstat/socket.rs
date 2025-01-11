use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct Socket {
    pub local_addr: String,
    pub remote_addr: String,
    pub protocol: String,
    pub pid: u32,
    pub state: String,
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
    Unix,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Tcp6 => "tcp6",
            Protocol::Udp => "udp",
            Protocol::Udp6 => "udp6",
            Protocol::Unix => "unix",
        }
    }
}

pub fn tcp_state_to_string(state: u8) -> String {
    match state {
        1 => "ESTABLISHED".to_string(),
        2 => "SYN_SENT".to_string(),
        3 => "SYN_RECV".to_string(),
        4 => "FIN_WAIT1".to_string(),
        5 => "FIN_WAIT2".to_string(),
        6 => "TIME_WAIT".to_string(),
        7 => "CLOSE".to_string(),
        8 => "CLOSE_WAIT".to_string(),
        9 => "LAST_ACK".to_string(),
        10 => "LISTEN".to_string(),
        11 => "CLOSING".to_string(),
        _ => format!("UNKNOWN({})", state),
    }
}

pub fn format_ip(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(addr) => format!("{}:{}", addr, port),
        IpAddr::V6(addr) => format!("[{}]:{}", addr, port),
    }
}

pub fn parse_hex_ip_v4(hex: &str) -> Option<(Ipv4Addr, u16)> {
    if hex.len() != 8 {
        return None;
    }
    let addr = u32::from_str_radix(hex, 16).ok()?;
    let port = (addr & 0xFFFF) as u16;
    let ip = Ipv4Addr::from((addr >> 16) as u32);
    Some((ip, port))
}

pub fn parse_hex_ip_v6(hex: &str) -> Option<(Ipv6Addr, u16)> {
    if hex.len() != 32 {
        return None;
    }
    let mut segments = [0u16; 8];
    for i in 0..8 {
        segments[i] = u16::from_str_radix(&hex[i * 4..(i + 1) * 4], 16).ok()?;
    }
    let ip = Ipv6Addr::from(segments);
    let port = u16::from_str_radix(&hex[32..36], 16).ok()?;
    Some((ip, port))
}
