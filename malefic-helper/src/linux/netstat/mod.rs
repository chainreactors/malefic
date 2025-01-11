mod netlink;
mod procfs;
mod socket;

use socket::{Protocol, Socket};
use std::io::Error;

pub fn get_sockets(ipv4: bool, ipv6: bool, tcp: bool, udp: bool) -> Result<Vec<Socket>, Error> {
    let mut sockets = Vec::new();

    // 首先尝试使用 netlink 接口
    let use_netlink = || -> Result<Vec<Socket>, Error> {
        let mut sockets = Vec::new();
        if tcp {
            if ipv4 {
                sockets.extend(netlink::get_sockets_netlink(Protocol::Tcp)?);
            }
            if ipv6 {
                sockets.extend(netlink::get_sockets_netlink(Protocol::Tcp6)?);
            }
        }

        if udp {
            if ipv4 {
                sockets.extend(netlink::get_sockets_netlink(Protocol::Udp)?);
            }
            if ipv6 {
                sockets.extend(netlink::get_sockets_netlink(Protocol::Udp6)?);
            }
        }

        // 添加 Unix domain sockets
        sockets.extend(netlink::get_sockets_netlink(Protocol::Unix)?);

        Ok(sockets)
    };

    // 如果 netlink 失败，回退到 procfs
    match use_netlink() {
        Ok(netlink_sockets) => {
            sockets.extend(netlink_sockets);
        }
        Err(_) => {
            if tcp {
                if ipv4 {
                    sockets.extend(procfs::read_proc_net_file(Protocol::Tcp, "/proc/net/tcp")?);
                }
                if ipv6 {
                    sockets.extend(procfs::read_proc_net_file(
                        Protocol::Tcp6,
                        "/proc/net/tcp6",
                    )?);
                }
            }

            if udp {
                if ipv4 {
                    sockets.extend(procfs::read_proc_net_file(Protocol::Udp, "/proc/net/udp")?);
                }
                if ipv6 {
                    sockets.extend(procfs::read_proc_net_file(
                        Protocol::Udp6,
                        "/proc/net/udp6",
                    )?);
                }
            }

            // 回退到 procfs 时也要添加 Unix domain sockets
            sockets.extend(procfs::read_proc_net_file(
                Protocol::Unix,
                "/proc/net/unix",
            )?);
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
            if socket.protocol == "tcp" {
                assert!(!socket.local_addr.is_empty());
                assert!(!socket.state.is_empty());
            }
        }
    }

    #[test]
    fn test_udp_sockets() {
        let sockets = get_sockets(true, false, false, true).unwrap();
        for socket in sockets {
            if socket.protocol == "udp" {
                assert!(!socket.local_addr.is_empty());
                assert!(socket.state.is_empty());
                assert!(socket.remote_addr.is_empty());
            }
        }
    }

    #[test]
    fn test_unix_sockets() {
        let sockets = get_sockets(false, false, false, false).unwrap();
        let unix_sockets: Vec<_> = sockets
            .into_iter()
            .filter(|s| s.protocol == "unix")
            .collect();
        assert!(!unix_sockets.is_empty(), "Should get some Unix sockets");
        for socket in unix_sockets {
            assert_eq!(socket.protocol, "unix");
            assert!(!socket.state.is_empty());
        }
    }
}
