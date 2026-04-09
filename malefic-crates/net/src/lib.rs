#[cfg(target_os = "macos")]
pub mod darwin;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod win;

#[cfg(target_os = "macos")]
use darwin as netstat;
#[cfg(any(target_os = "linux", target_os = "android"))]
use linux as netstat;
#[cfg(target_os = "windows")]
use win as netstat;

use malefic_common::errors::CommonError;
use malefic_common::to_error;
use malefic_gateway::ObfDebug;

#[derive(ObfDebug, Clone)]
pub struct NetInterface {
    pub index: u32,
    pub name: String,
    pub mac: String,
    pub ips: Vec<String>,
}

pub fn get_network_interfaces() -> Result<Vec<NetInterface>, CommonError> {
    Ok(Vec::new())
}

#[derive(ObfDebug, Clone)]
pub struct NetStat {
    pub local_addr: String,
    pub remote_addr: String,
    pub protocol: String,
    pub pid: String,
    pub sk_state: String,
}

pub fn get_netstat() -> Result<Vec<NetStat>, CommonError> {
    let mut netstats = Vec::new();
    let sockets = to_error!(netstat::get_sockets(true, true, true, true))?;
    for socket in sockets {
        netstats.push(NetStat {
            local_addr: socket.local_addr,
            remote_addr: socket.remote_addr,
            protocol: socket.protocol,
            pid: socket.pid.to_string(),
            sk_state: socket.state,
        });
    }
    Ok(netstats)
}
