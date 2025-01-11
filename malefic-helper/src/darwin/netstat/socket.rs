use std::net::{IpAddr};

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
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Tcp6 => "tcp6",
            Protocol::Udp => "udp",
            Protocol::Udp6 => "udp6",
        }
    }
}

pub fn tcp_state_to_string(state: u8) -> String {
    match state {
        0 => "CLOSED".to_string(),
        1 => "LISTEN".to_string(),
        2 => "SYN_SENT".to_string(),
        3 => "SYN_RCVD".to_string(),
        4 => "ESTABLISHED".to_string(),
        5 => "CLOSE_WAIT".to_string(),
        6 => "FIN_WAIT_1".to_string(),
        7 => "CLOSING".to_string(),
        8 => "LAST_ACK".to_string(),
        9 => "FIN_WAIT_2".to_string(),
        10 => "TIME_WAIT".to_string(),
        _ => format!("UNKNOWN({})", state),
    }
}

pub fn format_ip(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(addr) => format!("{}:{}", addr, port),
        IpAddr::V6(addr) => format!("[{}]:{}", addr, port),
    }
}
