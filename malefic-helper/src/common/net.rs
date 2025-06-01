use crate::{to_error, CommonError};

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
