use super::socket::{format_ip, tcp_state_to_string, Protocol, Socket};
use super::libproc_bindings::*;
use std::io::Error;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};

const NET_TCP_PCBLIST: i32 = 4;
const NET_UDP_PCBLIST: i32 = 4;
const PROX_FDTYPE_SOCKET: i32 = 2;

#[repr(C)]
struct XProcFdInfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

#[repr(C)]
struct XSockBuf {
    cc: u32,
    hiwat: u32,
    mbcnt: u32,
    mbmax: u32,
    lowat: u32,
    sb_flags: u32,
    sb_timeo: i16,
}

#[repr(C)]
struct XSocket {
    xso_len: u32,
    xso_kind: u32,
    xso_protocol: u32,
    xso_family: u32,
    xso_pcb: u64,
    xso_inpcb: u64,
    xso_rcv: XSockBuf,
    xso_snd: XSockBuf,
    so_state: u32,
    so_options: i16,
    so_linger: i16,
    so_timeo: i16,
    so_error: u16,
    so_pgid: u32,
    so_oobmark: u32,
    so_uid: u32,
}

#[repr(C)]
struct XInPcb {
    xi_len: u32,
    xi_kind: u32,
    xi_inpp: u64,
    xi_socket: u64,
    xi_fport: u16,
    xi_lport: u16,
    xi_faddr: [u32; 4],
    xi_laddr: [u32; 4],
    xi_socket_family: u32,
    inp_flags: u32,
    inp_flow: u32,
    inp_vflag: u8,
    inp_ip_ttl: u8,
    inp_ip_p: u8,
    inp_dependfaddr: u8,
    inp_dependladdr: u8,
    inp_depend6: u8,
    inp_depend4: u8,
    _padding: u8,
}

pub fn get_sockets_sysctl(protocol: Protocol) -> Result<Vec<Socket>, Error> {
    let mib = match protocol {
        Protocol::Tcp | Protocol::Tcp6 => vec![
            libc::CTL_NET,
            libc::AF_INET,
            libc::IPPROTO_TCP,
            NET_TCP_PCBLIST,
        ],
        Protocol::Udp | Protocol::Udp6 => vec![
            libc::CTL_NET,
            libc::AF_INET,
            libc::IPPROTO_UDP,
            NET_UDP_PCBLIST,
        ],
    };

    let mut len = 0;
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr() as *mut _,
            mib.len() as u32,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };

    if ret < 0 {
        return Err(Error::last_os_error());
    }

    let mut buf = vec![0u8; len];
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr() as *mut _,
            mib.len() as u32,
            buf.as_mut_ptr() as *mut _,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };

    if ret < 0 {
        return Err(Error::last_os_error());
    }

    let mut sockets = Vec::new();
    let mut offset = 0;
    let current_pid = unsafe { libc::getpid() };

    while offset < len {
        let xsocket = unsafe { &*(buf.as_ptr().add(offset) as *const XSocket) };
        offset += xsocket.xso_len as usize;

        if xsocket.xso_protocol != protocol.as_proto() as u32 {
            continue;
        }

        let xinpcb = unsafe { &*(buf.as_ptr().add(offset) as *const XInPcb) };
        offset += xinpcb.xi_len as usize;

        let is_ipv6 = xinpcb.inp_vflag & 0x2 != 0;
        if (is_ipv6 && !matches!(protocol, Protocol::Tcp6 | Protocol::Udp6))
            || (!is_ipv6 && !matches!(protocol, Protocol::Tcp | Protocol::Udp))
        {
            continue;
        }

        let (local_addr, remote_addr) = if is_ipv6 {
            (
                format_ip(
                    Ipv6Addr::from([
                        ((xinpcb.xi_laddr[0] >> 16) & 0xFFFF) as u16,
                        (xinpcb.xi_laddr[0] & 0xFFFF) as u16,
                        ((xinpcb.xi_laddr[1] >> 16) & 0xFFFF) as u16,
                        (xinpcb.xi_laddr[1] & 0xFFFF) as u16,
                        ((xinpcb.xi_laddr[2] >> 16) & 0xFFFF) as u16,
                        (xinpcb.xi_laddr[2] & 0xFFFF) as u16,
                        ((xinpcb.xi_laddr[3] >> 16) & 0xFFFF) as u16,
                        (xinpcb.xi_laddr[3] & 0xFFFF) as u16,
                    ])
                    .into(),
                    u16::from_be(xinpcb.xi_lport),
                ),
                format_ip(
                    Ipv6Addr::from([
                        ((xinpcb.xi_faddr[0] >> 16) & 0xFFFF) as u16,
                        (xinpcb.xi_faddr[0] & 0xFFFF) as u16,
                        ((xinpcb.xi_faddr[1] >> 16) & 0xFFFF) as u16,
                        (xinpcb.xi_faddr[1] & 0xFFFF) as u16,
                        ((xinpcb.xi_faddr[2] >> 16) & 0xFFFF) as u16,
                        (xinpcb.xi_faddr[2] & 0xFFFF) as u16,
                        ((xinpcb.xi_faddr[3] >> 16) & 0xFFFF) as u16,
                        (xinpcb.xi_faddr[3] & 0xFFFF) as u16,
                    ])
                    .into(),
                    u16::from_be(xinpcb.xi_fport),
                ),
            )
        } else {
            (
                format_ip(
                    Ipv4Addr::from(u32::from_be(xinpcb.xi_laddr[0])).into(),
                    u16::from_be(xinpcb.xi_lport),
                ),
                format_ip(
                    Ipv4Addr::from(u32::from_be(xinpcb.xi_faddr[0])).into(),
                    u16::from_be(xinpcb.xi_fport),
                ),
            )
        };

        sockets.push(Socket {
            local_addr,
            remote_addr,
            protocol: protocol.as_str().to_string(),
            pid: if xsocket.xso_pcb == 0 {
                current_pid as u32
            } else {
                get_socket_pid(xsocket.xso_pcb)?
            },
            state: match protocol {
                Protocol::Tcp | Protocol::Tcp6 => {
                    tcp_state_to_string((xsocket.so_state & 0xFF) as u8)
                }
                _ => String::new(),
            },
        });
    }

    Ok(sockets)
}

fn get_socket_pid(pcb: u64) -> Result<u32, Error> {
    let mut kinfo = vec![0u8; 1024];
    let mut len = kinfo.len();
    let pid = unsafe { libc::getpid() };
    let ret = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            kinfo.as_mut_ptr() as *mut _,
            len as i32,
        )
    };

    if ret < 0 {
        return Ok(0);
    }

    len = ret as usize;
    let mut offset = 0;

    while offset < len {
        let fdinfo = unsafe { &*(kinfo.as_ptr().add(offset) as *const XProcFdInfo) };
        offset += mem::size_of::<XProcFdInfo>();

        if fdinfo.proc_fdtype == PROX_FDTYPE_SOCKET as u32 {
            let mut socket_info = vec![0u8; mem::size_of::<XSocket>()];
            let ret = unsafe {
                proc_pidfdinfo(
                    pid,
                    fdinfo.proc_fd,
                    PROC_PIDFDSOCKETINFO,
                    socket_info.as_mut_ptr() as *mut _,
                    socket_info.len() as i32,
                )
            };

            if ret > 0 {
                let xsocket = unsafe { &*(socket_info.as_ptr() as *const XSocket) };
                if xsocket.xso_pcb == pcb {
                    return Ok(pid as u32);
                }
            }
        }
    }

    Ok(0)
}

trait ProtocolExt {
    fn as_proto(&self) -> i32;
}

impl ProtocolExt for Protocol {
    fn as_proto(&self) -> i32 {
        match self {
            Protocol::Tcp | Protocol::Tcp6 => libc::IPPROTO_TCP,
            Protocol::Udp | Protocol::Udp6 => libc::IPPROTO_UDP,
        }
    }
}
