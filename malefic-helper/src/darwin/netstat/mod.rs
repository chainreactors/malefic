mod socket;
mod sysctl;

mod libproc_bindings;
use socket::{Protocol, Socket};
use std::io::Error;

pub fn get_sockets(ipv4: bool, ipv6: bool, tcp: bool, udp: bool) -> Result<Vec<Socket>, Error> {
    let mut sockets = Vec::new();

    if tcp {
        if ipv4 {
            sockets.extend(sysctl::get_sockets_sysctl(Protocol::Tcp)?);
        }
        if ipv6 {
            sockets.extend(sysctl::get_sockets_sysctl(Protocol::Tcp6)?);
        }
    }

    if udp {
        if ipv4 {
            sockets.extend(sysctl::get_sockets_sysctl(Protocol::Udp)?);
        }
        if ipv6 {
            sockets.extend(sysctl::get_sockets_sysctl(Protocol::Udp6)?);
        }
    }

    Ok(sockets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_sockets() {
        let sockets = get_sockets(true, true, true, true).unwrap();
        assert!(!sockets.is_empty(), "Should get some sockets");
    }

    #[test]
    fn test_tcp_sockets() {
        let sockets = get_sockets(true, false, true, false).unwrap();
        for socket in sockets {
            assert_eq!(socket.protocol, "tcp");
            assert!(!socket.local_addr.is_empty());
            assert!(!socket.state.is_empty());
        }
    }

    #[test]
    fn test_udp_sockets() {
        let sockets = get_sockets(true, false, false, true).unwrap();
        for socket in sockets {
            assert_eq!(socket.protocol, "udp");
            assert!(!socket.local_addr.is_empty());
            assert!(socket.state.is_empty());
            assert!(socket.remote_addr.is_empty());
        }
    }
}
