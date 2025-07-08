use super::socket::{Protocol, Socket, TcpState, TcpSocketInfo, UdpSocketInfo, ProtocolSocketInfo};
use crate::darwin::netstat::libproc_bindings::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use std::{io, mem};
use std::ptr;
use libc::{self, PF_INET, AF_INET6,AF_INET, IPPROTO_TCP, IPPROTO_UDP};
use std::fs::OpenOptions;
use std::io::Write;
use byteorder::{ByteOrder, NetworkEndian};
// macOS specific sysctl MIB names
const NET_RT_IFLIST2: i32 = 6;
const PF_ROUTE: i32 = 17;
const NET_RT_STAT: i32 = 12;
const TCPCTL_PCBLIST: i32 = 1;
const UDPCTL_PCBLIST: i32 = 1;
use std::os::raw::{c_int, c_void};
const PROX_FDTYPE_SOCKET: i32 = 2;
const SYSCTL_TIMEOUT: Duration = Duration::from_secs(3);

pub type PID = c_int;

#[repr(C)]
struct XInPcb {
    xi_len: u32,
    xi_kind: u32,
    xi_socket_family: u32,
    xi_socket_type: u32,
    xi_socket_protocol: u32,
    xi_socket_state: u32,
    xi_socket_pcb: u64,
    xi_laddr: [u32; 4],
    xi_faddr: [u32; 4],
    xi_lport: u16,
    xi_fport: u16,
    inp_vflag: u8,
    inp_ip_ttl: u8,
    inp_ip_p: u8,
    pad: u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum ProcFDType {
    Atalk = 0,
    Vnode = 1,
    Socket = 2,
    PSHM = 3,
    PSEM = 4,
    Kqueue = 5,
    Pipe = 6,
    FsEvents = 7,
    NetPolicy = 9,
}

impl ProcFDType {
    fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(ProcFDType::Atalk),
            1 => Some(ProcFDType::Vnode),
            2 => Some(ProcFDType::Socket),
            3 => Some(ProcFDType::PSHM),
            4 => Some(ProcFDType::PSEM),
            5 => Some(ProcFDType::Kqueue),
            6 => Some(ProcFDType::Pipe),
            7 => Some(ProcFDType::FsEvents),
            9 => Some(ProcFDType::NetPolicy),
            _ => None,
        }
    }
}


pub struct ProcFDInfo {
    pub proc_fd: i32,
    pub proc_fdtype: ProcFDType,
}

impl Default for ProcFDInfo {
    fn default() -> Self {
        ProcFDInfo {
            proc_fd: 0,
            proc_fdtype: ProcFDType::Atalk,
        }
    }
}


impl ProcFDInfo {
    fn try_from_proc_fdinfo(other: proc_fdinfo) -> Result<Self, io::Error> {
        Ok(ProcFDInfo {
            proc_fd: other.proc_fd,
            proc_fdtype: ProcFDType::from_u32(other.proc_fdtype)
                .ok_or_else(|| io::Error::last_os_error())?,
        })
    }
}

pub fn list_all_fds_for_pid(pid: PID) -> Result<Vec<ProcFDInfo>, io::Error> {
    // We need to call proc_pidinfo twice, one time to get needed buffer size.
    // A second time to actually populate buffer.
    let buffer_size = unsafe {
        proc_pidinfo(
            pid as c_int,
            PROC_PIDLISTFDS as c_int,
            0,
            ptr::null_mut(),
            0,
        )
    };

    if buffer_size <= 0 {
        return Err(io::Error::last_os_error());
    }

    let number_of_fds = buffer_size as usize / mem::size_of::<proc_fdinfo>();

    let mut fds: Vec<proc_fdinfo> = Vec::new();
    fds.resize_with(number_of_fds as usize, || proc_fdinfo {
        proc_fd: 0,
        proc_fdtype: 0,
    });

    let return_code = unsafe {
        proc_pidinfo(
            pid as c_int,
            PROC_PIDLISTFDS as c_int,
            0,
            fds.as_mut_ptr() as *mut c_void,
            buffer_size,
        )
    };

    if return_code <= 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fds
            .into_iter()
            .map(|fd| ProcFDInfo::try_from_proc_fdinfo(fd).unwrap_or_default())
            .collect())
    }
}

pub fn get_sockets_sysctl(protocol: Protocol) -> Result<Vec<Socket>, io::Error> {
    let mut sockets = Vec::new();
    
    // 获取所有进程的 PID
    let number_of_pids = unsafe {
        proc_listpids(1, 0, std::ptr::null_mut(), 0)
    };

    if number_of_pids < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut pids = vec![0i32; number_of_pids as usize];
    let return_code = unsafe {
        proc_listpids(
            1,
            0,
            pids.as_mut_ptr() as *mut _,
            (pids.len() * std::mem::size_of::<i32>()) as i32,
        )
    };

    if return_code <= 0 {
        return Err(io::Error::last_os_error());
    }

    // 过滤掉无效的 PID
    let pids: Vec<i32> = pids.into_iter().filter(|&pid| pid > 0).collect();

    // 遍历每个进程
    for pid in pids {
        let fds = match list_all_fds_for_pid(pid) {
            Ok(fds) => fds,
            Err(_) => continue, // 权限不足直接跳过
        };

        // 遍历文件描述符
        for fd in &fds {
            if fd.proc_fdtype as i32 != PROX_FDTYPE_SOCKET {
                continue;
            }

            let mut socket_buffer = vec![0u8; std::mem::size_of::<socket_fdinfo>()];
            let socket_size = unsafe {
                proc_pidfdinfo(
                    pid,
                    fd.proc_fd,
                    PROC_PIDFDSOCKETINFO as i32,
                    socket_buffer.as_mut_ptr() as *mut _,
                    socket_buffer.len() as i32,
                )
            };
            if socket_size < 0 {
                continue;
            }

            let socket_info = unsafe { &*(socket_buffer.as_ptr() as *const socket_fdinfo) };

            // 检查协议类型
            let is_ipv6 = socket_info.psi.soi_family == AF_INET6 as i32;
            let is_ipv6_protocol = matches!(protocol, Protocol::Tcp6 | Protocol::Udp6);
            // if is_ipv6 != is_ipv6_protocol {
            //     continue;
            // }

            // 检查协议
            let is_tcp = socket_info.psi.soi_protocol == libc::IPPROTO_TCP as i32;
            let is_udp = socket_info.psi.soi_protocol == libc::IPPROTO_UDP as i32;
            let is_tcp_protocol = matches!(protocol, Protocol::Tcp | Protocol::Tcp6);
            let is_udp_protocol = matches!(protocol, Protocol::Udp | Protocol::Udp6);
            // if !((is_tcp && is_tcp_protocol) || (is_udp && is_udp_protocol)) {
            //     continue;
            // }

            let protocol_socket_info = if is_tcp {
                if let Some(tcp_info) = parse_tcp_socket_info(socket_info) {
                    ProtocolSocketInfo::Tcp(tcp_info)
                } else {
                    continue;
                }
            } else {
                if let Some(udp_info) = parse_udp_socket_info(socket_info) {
                    ProtocolSocketInfo::Udp(udp_info)
                } else {
                    continue;
                }
            };

            sockets.push(Socket::new(protocol_socket_info, pid as u32));
        }
    }
    Ok(sockets)
}

pub fn parse_tcp_socket_info(sinfo: &socket_fdinfo) -> Option<TcpSocketInfo> {
    use std::convert::TryInto;

    if sinfo.psi.soi_family != AF_INET as i32 && sinfo.psi.soi_family != AF_INET6 as i32 {
        return None;
    }
    if sinfo.psi.soi_protocol != IPPROTO_TCP as i32 {
        return None;
    }

    let is_ipv6 = sinfo.psi.soi_family == AF_INET6 as i32;

    let ini = unsafe { &sinfo.psi.soi_proto.pri_tcp.tcpsi_ini };

    let local_addr = if is_ipv6 {
        let addr = unsafe { ini.insi_laddr.ina_6.__u6_addr.__u6_addr8 };
        IpAddr::V6(Ipv6Addr::from(addr))
    } else {
        let addr = unsafe { ini.insi_laddr.ina_46.i46a_addr4.s_addr };
        IpAddr::V4(Ipv4Addr::from(u32::from_be(addr)))
    };

    let remote_addr = if is_ipv6 {
        let addr = unsafe { ini.insi_faddr.ina_6.__u6_addr.__u6_addr8 };
        IpAddr::V6(Ipv6Addr::from(addr))
    } else {
        let addr = unsafe { ini.insi_faddr.ina_46.i46a_addr4.s_addr };
        IpAddr::V4(Ipv4Addr::from(u32::from_be(addr)))
    };

    let local_port = u16::from_be(ini.insi_lport as u16);
    let remote_port = u16::from_be(ini.insi_fport as u16);

    let state = match unsafe { sinfo.psi.soi_proto.pri_tcp.tcpsi_state } {
        0 => TcpState::Closed,
        1 => TcpState::Listen,
        2 => TcpState::SynSent,
        3 => TcpState::SynReceived,
        4 => TcpState::Established,
        5 => TcpState::CloseWait,
        6 => TcpState::FinWait1,
        7 => TcpState::Closing,
        8 => TcpState::LastAck,
        9 => TcpState::FinWait2,
        10 => TcpState::TimeWait,
        _ => TcpState::Closed,
    };

    Some(TcpSocketInfo {
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state,
    })
}

pub fn parse_udp_socket_info(sinfo: &socket_fdinfo) -> Option<UdpSocketInfo> {
    if sinfo.psi.soi_family != AF_INET as i32 && sinfo.psi.soi_family != AF_INET6 as i32 {
        return None;
    }
    if sinfo.psi.soi_protocol != IPPROTO_UDP as i32 {
        return None;
    }

    let is_ipv6 = sinfo.psi.soi_family == AF_INET6 as i32;

    let ini = unsafe { &sinfo.psi.soi_proto.pri_in };

    let local_addr = if is_ipv6 {
        let addr = unsafe { ini.insi_faddr.ina_6.__u6_addr.__u6_addr8 };
        IpAddr::V6(Ipv6Addr::from(addr))
    } else {
        let addr = unsafe { ini.insi_laddr.ina_46.i46a_addr4.s_addr };
        IpAddr::V4(Ipv4Addr::from(u32::from_be(addr)))
    };

    let local_port = u16::from_be(ini.insi_lport as u16);

    Some(UdpSocketInfo {
        local_addr,
        local_port,
    })
}
