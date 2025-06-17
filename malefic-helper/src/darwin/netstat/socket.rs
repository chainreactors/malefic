use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq)]
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    CloseWait,
    FinWait1,
    Closing,
    LastAck,
    FinWait2,
    TimeWait,
}

impl TcpState {
    pub fn to_string(&self) -> String {
        match self {
            TcpState::Closed => "CLOSED".to_string(),
            TcpState::Listen => "LISTEN".to_string(),
            TcpState::SynSent => "SYN_SENT".to_string(),
            TcpState::SynReceived => "SYN_RECEIVED".to_string(),
            TcpState::Established => "ESTABLISHED".to_string(),
            TcpState::CloseWait => "CLOSE_WAIT".to_string(),
            TcpState::FinWait1 => "FIN_WAIT_1".to_string(),
            TcpState::Closing => "CLOSING".to_string(),
            TcpState::LastAck => "LAST_ACK".to_string(),
            TcpState::FinWait2 => "FIN_WAIT_2".to_string(),
            TcpState::TimeWait => "TIME_WAIT".to_string(),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynReceived => "SYN_RECEIVED",
            TcpState::Established => "ESTABLISHED",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::FinWait1 => "FIN_WAIT_1",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::FinWait2 => "FIN_WAIT_2",
            TcpState::TimeWait => "TIME_WAIT",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpSocketInfo {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub state: TcpState,
}

#[derive(Debug, Clone)]
pub struct UdpSocketInfo {
    pub local_addr: IpAddr,
    pub local_port: u16,
}

#[derive(Debug, Clone)]
pub enum ProtocolSocketInfo {
    Tcp(TcpSocketInfo),
    Udp(UdpSocketInfo),
}

#[derive(Debug, Clone)]
pub struct Socket {
    pub protocol_socket_info: ProtocolSocketInfo,
    pub pid: u32,
    pub local_addr: String,
    pub remote_addr: String,
    pub protocol: String,
    pub state: String,
}

impl Socket {
    pub fn new(protocol_socket_info: ProtocolSocketInfo, pid: u32) -> Self {
        let (local_addr, remote_addr, protocol, state) = match &protocol_socket_info {
            ProtocolSocketInfo::Tcp(info) => (
                format!("{}:{}", format_ip(info.local_addr), info.local_port),
                format!("{}:{}", format_ip(info.remote_addr), info.remote_port),
                String::from("tcp"),
                info.state.to_string(),
            ),
            ProtocolSocketInfo::Udp(info) => (
                format!("{}:{}", format_ip(info.local_addr), info.local_port),
                String::new(),
                String::from("udp"),
                String::new(),
            ),
        };

        Self {
            protocol_socket_info,
            pid,
            local_addr,
            remote_addr,
            protocol,
            state,
        }
    }
}

pub fn format_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => {
            if ip.is_unspecified() {
                "::".to_string()
            } else {
                ip.to_string()
            }
        }
    }
}

pub fn tcp_state_to_string(state: u8) -> String {
    match state {
        0 => "CLOSED",
        1 => "LISTEN",
        2 => "SYN_SENT",
        3 => "SYN_RECEIVED",
        4 => "ESTABLISHED",
        5 => "CLOSE_WAIT",
        6 => "FIN_WAIT_1",
        7 => "CLOSING",
        8 => "LAST_ACK",
        9 => "FIN_WAIT_2",
        10 => "TIME_WAIT",
        _ => "UNKNOWN",
    }.to_string()
}
