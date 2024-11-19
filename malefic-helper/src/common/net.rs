use netstat2::{AddressFamilyFlags, get_sockets_info, ProtocolFlags, ProtocolSocketInfo};
use crate::{to_error, CommonError};

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct NetInterface {
    pub index: u32,
    pub name: String,
    pub mac: String,
    pub ips: Vec<String>,
}

pub fn get_network_interfaces() -> Result<Vec<NetInterface>, CommonError> {
    let interfaces = Vec::new();
    Ok(interfaces)
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct NetStat {
    pub local_addr: String,
    pub remote_addr: String,
    pub protocol: String,
    pub pid: String,
    // pub uid: u32,
    pub sk_state: String,
}

pub fn get_netstat() -> Result<Vec<NetStat>, CommonError> {
    let mut netstats = Vec::new();
 
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets_info = to_error!(get_sockets_info(af_flags, proto_flags))?;

    for si in sockets_info {
        let pid: Vec<String> = si.associated_pids.iter().map(|n| n.to_string()).collect();
        match si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp_si) => {
                netstats.push(NetStat{
                    local_addr: tcp_si.local_addr.to_string(),
                    remote_addr: tcp_si.remote_addr.to_string(),
                    protocol: "tcp".to_string(),
                    pid: pid.join(","),
                    sk_state: tcp_si.state.to_string()
                })
            },
            ProtocolSocketInfo::Udp(udp_si) => {
                netstats.push(NetStat{
                    local_addr: udp_si.local_addr.to_string(),
                    remote_addr: "".to_string(),
                    protocol: "udp".to_string(),
                    pid: pid.join(","),
                    sk_state: "".to_string()
                })
            }
        }
    }
    Ok(netstats)
}