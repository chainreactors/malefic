use super::socket::{format_ip, tcp_state_to_string, Protocol, Socket};
use std::io::{Error, ErrorKind};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};

#[repr(C)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
struct InetDiagReqV2 {
    family: u8,
    protocol: u8,
    ext: u8,
    pad: u8,
    states: u32,
    id: InetDiagSockId,
}

#[repr(C)]
struct InetDiagSockId {
    sport: u16,
    dport: u16,
    src: [u32; 4],
    dst: [u32; 4],
    if_idx: u32,
    cookie: [u32; 2],
}

#[repr(C)]
struct InetDiagMsg {
    family: u8,
    state: u8,
    timer: u8,
    retrans: u8,
    id: InetDiagSockId,
    expires: u32,
    rqueue: u32,
    wqueue: u32,
    uid: u32,
    inode: u32,
}

#[repr(C)]
struct UnixDiagReq {
    family: u8,
    protocol: u8,
    pad: u16,
    states: u32,
    ino: u32,
    show: u32,
    cookie: [u32; 2],
}

#[repr(C)]
struct UnixDiagMsg {
    family: u8,
    pad1: u8,
    pad2: u16,
    ino: u32,
    cookie: [u32; 2],
    state: u32,
    flags: u32,
    type_: u32,
    pad3: u32,
}

#[repr(C)]
struct NlAttr {
    nla_len: u16,
    nla_type: u16,
}

const NLMSG_ALIGNTO: usize = 4;
const NLMSG_HDRLEN: usize = mem::size_of::<NlMsgHdr>();
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const TCPF_ALL: u32 = 0xFFF;
const UDIAG_SHOW_NAME: u32 = 0x01;
const UDIAG_SHOW_PEER: u32 = 0x04;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const SOCK_SEQPACKET: u32 = 5;
const UNIX_STATE_UNCONNECTED: u32 = 0;
const UNIX_STATE_CONNECTED: u32 = 1;
const UNIX_STATE_LISTENING: u32 = 2;
const UNIX_STATE_DISCONNECTING: u32 = 3;
const UNIX_STATE_DISCONNECTED: u32 = 4;

fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

pub fn get_sockets_netlink(protocol: Protocol) -> Result<Vec<Socket>, Error> {
    match protocol {
        Protocol::Tcp | Protocol::Tcp6 | Protocol::Udp | Protocol::Udp6 => {
            get_inet_sockets(protocol)
        }
        Protocol::Unix => get_unix_sockets_netlink(),
    }
}

fn get_inet_sockets(protocol: Protocol) -> Result<Vec<Socket>, Error> {
    let sock = create_netlink_socket()?;
    let family = match protocol {
        Protocol::Tcp | Protocol::Udp => libc::AF_INET,
        Protocol::Tcp6 | Protocol::Udp6 => libc::AF_INET6,
        _ => unreachable!(),
    };

    let proto = match protocol {
        Protocol::Tcp | Protocol::Tcp6 => libc::IPPROTO_TCP,
        Protocol::Udp | Protocol::Udp6 => libc::IPPROTO_UDP,
        _ => unreachable!(),
    };

    let req = create_inet_request(family as u8, proto as u8)?;
    send_netlink_request(sock, &req)?;
    let resp = receive_netlink_response(sock)?;
    unsafe { libc::close(sock) };

    parse_inet_response(resp, protocol)
}

fn get_unix_sockets_netlink() -> Result<Vec<Socket>, Error> {
    let sock = create_netlink_socket()?;
    let req = create_unix_request()?;
    send_netlink_request(sock, &req)?;
    let resp = receive_netlink_response(sock)?;
    unsafe { libc::close(sock) };

    parse_unix_response(resp)
}

fn create_netlink_socket() -> Result<i32, Error> {
    let sock = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };

    if sock < 0 {
        return Err(Error::last_os_error());
    }

    let addr = unsafe {
        let mut addr: libc::sockaddr_nl = mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as u16;
        addr
    };

    let bind_result = unsafe {
        libc::bind(
            sock,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };

    if bind_result < 0 {
        let err = Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(err);
    }

    Ok(sock)
}

fn create_inet_request(family: u8, protocol: u8) -> Result<Vec<u8>, Error> {
    let req = InetDiagReqV2 {
        family,
        protocol,
        ext: 0,
        pad: 0,
        states: TCPF_ALL,
        id: InetDiagSockId {
            sport: 0,
            dport: 0,
            src: [0; 4],
            dst: [0; 4],
            if_idx: 0,
            cookie: [0; 2],
        },
    };

    let nlh = NlMsgHdr {
        nlmsg_len: (NLMSG_HDRLEN + mem::size_of::<InetDiagReqV2>()) as u32,
        nlmsg_type: SOCK_DIAG_BY_FAMILY,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let mut buf = vec![0u8; nlh.nlmsg_len as usize];
    unsafe {
        let nlh_ptr = buf.as_mut_ptr() as *mut NlMsgHdr;
        *nlh_ptr = nlh;
        let req_ptr = buf.as_mut_ptr().add(NLMSG_HDRLEN) as *mut InetDiagReqV2;
        *req_ptr = req;
    }

    Ok(buf)
}

fn create_unix_request() -> Result<Vec<u8>, Error> {
    let req = UnixDiagReq {
        family: libc::AF_UNIX as u8,
        protocol: 0,
        pad: 0,
        states: TCPF_ALL,
        ino: 0,
        show: UDIAG_SHOW_NAME | UDIAG_SHOW_PEER,
        cookie: [0; 2],
    };

    let nlh = NlMsgHdr {
        nlmsg_len: (NLMSG_HDRLEN + mem::size_of::<UnixDiagReq>()) as u32,
        nlmsg_type: SOCK_DIAG_BY_FAMILY,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let mut buf = vec![0u8; nlh.nlmsg_len as usize];
    unsafe {
        let nlh_ptr = buf.as_mut_ptr() as *mut NlMsgHdr;
        *nlh_ptr = nlh;
        let req_ptr = buf.as_mut_ptr().add(NLMSG_HDRLEN) as *mut UnixDiagReq;
        *req_ptr = req;
    }

    Ok(buf)
}

fn send_netlink_request(sock: i32, buf: &[u8]) -> Result<(), Error> {
    let sent = unsafe { libc::send(sock, buf.as_ptr() as *const libc::c_void, buf.len(), 0) };

    if sent < 0 {
        return Err(Error::last_os_error());
    }

    if sent != buf.len() as isize {
        return Err(Error::new(
            ErrorKind::Other,
            "Failed to send complete netlink message",
        ));
    }

    Ok(())
}

fn receive_netlink_response(sock: i32) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; 8192];
    let received = unsafe { libc::recv(sock, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

    if received < 0 {
        return Err(Error::last_os_error());
    }

    buf.truncate(received as usize);
    Ok(buf)
}

fn parse_inet_response(buf: Vec<u8>, protocol: Protocol) -> Result<Vec<Socket>, Error> {
    let mut sockets = Vec::new();
    let mut offset = 0;

    while offset < buf.len() {
        let nlh = unsafe { &*(buf.as_ptr().add(offset) as *const NlMsgHdr) };

        if nlh.nlmsg_type == libc::NLMSG_DONE as u16 {
            break;
        }

        if nlh.nlmsg_type == libc::NLMSG_ERROR as u16 {
            let err = unsafe { *(buf.as_ptr().add(offset + NLMSG_HDRLEN) as *const i32) };
            if err != 0 {
                return Err(Error::from_raw_os_error(-err));
            }
            break;
        }

        let diag_msg = unsafe { &*(buf.as_ptr().add(offset + NLMSG_HDRLEN) as *const InetDiagMsg) };

        let socket = parse_inet_diag_msg(diag_msg, protocol)?;
        sockets.push(socket);

        offset += nlmsg_align(nlh.nlmsg_len as usize);
    }

    Ok(sockets)
}

fn parse_unix_response(buf: Vec<u8>) -> Result<Vec<Socket>, Error> {
    let mut sockets = Vec::new();
    let mut offset = 0;

    while offset < buf.len() {
        let nlh = unsafe { &*(buf.as_ptr().add(offset) as *const NlMsgHdr) };

        if nlh.nlmsg_type == libc::NLMSG_DONE as u16 {
            break;
        }

        if nlh.nlmsg_type == libc::NLMSG_ERROR as u16 {
            let err = unsafe { *(buf.as_ptr().add(offset + NLMSG_HDRLEN) as *const i32) };
            if err != 0 {
                return Err(Error::from_raw_os_error(-err));
            }
            break;
        }

        let diag_msg = unsafe { &*(buf.as_ptr().add(offset + NLMSG_HDRLEN) as *const UnixDiagMsg) };
        let mut attr_offset = offset + NLMSG_HDRLEN + mem::size_of::<UnixDiagMsg>();
        let mut path = String::new();

        // Parse attributes to get the socket path
        while attr_offset < offset + nlh.nlmsg_len as usize {
            let attr = unsafe { &*(buf.as_ptr().add(attr_offset) as *const NlAttr) };
            if attr.nla_type == 0 {
                // UNIX_DIAG_NAME
                let data_ptr = unsafe { buf.as_ptr().add(attr_offset + mem::size_of::<NlAttr>()) };
                let data_len = attr.nla_len as usize - mem::size_of::<NlAttr>();
                path = String::from_utf8_lossy(
                    &buf[attr_offset + mem::size_of::<NlAttr>()..attr_offset + data_len],
                )
                .to_string();
                break;
            }
            attr_offset += nlmsg_align(attr.nla_len as usize);
        }

        let state = match diag_msg.type_ {
            SOCK_STREAM | SOCK_SEQPACKET => match diag_msg.state {
                UNIX_STATE_LISTENING => "LISTEN".to_string(),
                UNIX_STATE_CONNECTED => "ESTABLISHED".to_string(),
                UNIX_STATE_DISCONNECTING => "CLOSING".to_string(),
                UNIX_STATE_DISCONNECTED => "LAST_ACK".to_string(),
                UNIX_STATE_UNCONNECTED => "DISCONNECTED".to_string(),
                _ => "UNKNOWN".to_string(),
            },
            SOCK_DGRAM => "DGRAM".to_string(),
            _ => "UNKNOWN".to_string(),
        };

        sockets.push(Socket {
            local_addr: path,
            remote_addr: String::new(),
            protocol: "unix".to_string(),
            pid: super::procfs::find_process_by_inode(diag_msg.ino as u64).unwrap_or(0),
            state,
        });

        offset += nlmsg_align(nlh.nlmsg_len as usize);
    }

    Ok(sockets)
}

fn parse_inet_diag_msg(msg: &InetDiagMsg, protocol: Protocol) -> Result<Socket, Error> {
    let (local_addr, remote_addr) = if msg.family as i32 == libc::AF_INET {
        (
            format_ip(
                Ipv4Addr::from(u32::from_be(msg.id.src[0])).into(),
                u16::from_be(msg.id.sport),
            ),
            format_ip(
                Ipv4Addr::from(u32::from_be(msg.id.dst[0])).into(),
                u16::from_be(msg.id.dport),
            ),
        )
    } else {
        (
            format_ip(
                Ipv6Addr::from([
                    ((msg.id.src[0] >> 16) & 0xFFFF) as u16,
                    (msg.id.src[0] & 0xFFFF) as u16,
                    ((msg.id.src[1] >> 16) & 0xFFFF) as u16,
                    (msg.id.src[1] & 0xFFFF) as u16,
                    ((msg.id.src[2] >> 16) & 0xFFFF) as u16,
                    (msg.id.src[2] & 0xFFFF) as u16,
                    ((msg.id.src[3] >> 16) & 0xFFFF) as u16,
                    (msg.id.src[3] & 0xFFFF) as u16,
                ])
                .into(),
                u16::from_be(msg.id.sport),
            ),
            format_ip(
                Ipv6Addr::from([
                    ((msg.id.dst[0] >> 16) & 0xFFFF) as u16,
                    (msg.id.dst[0] & 0xFFFF) as u16,
                    ((msg.id.dst[1] >> 16) & 0xFFFF) as u16,
                    (msg.id.dst[1] & 0xFFFF) as u16,
                    ((msg.id.dst[2] >> 16) & 0xFFFF) as u16,
                    (msg.id.dst[2] & 0xFFFF) as u16,
                    ((msg.id.dst[3] >> 16) & 0xFFFF) as u16,
                    (msg.id.dst[3] & 0xFFFF) as u16,
                ])
                .into(),
                u16::from_be(msg.id.dport),
            ),
        )
    };

    let pid = find_pid_by_uid_and_inode(msg.uid, msg.inode as u64)
        .or_else(|| super::procfs::find_process_by_inode(msg.inode as u64))
        .unwrap_or(0);

    Ok(Socket {
        local_addr,
        remote_addr,
        protocol: protocol.as_str().to_string(),
        pid,
        state: match protocol {
            Protocol::Tcp | Protocol::Tcp6 => tcp_state_to_string(msg.state),
            _ => String::new(),
        },
    })
}

fn find_pid_by_uid_and_inode(uid: u32, inode: u64) -> Option<u32> {
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // 检查是否是数字（PID）目录
            if let Some(pid_str) = path.file_name() {
                if let Some(pid_str) = pid_str.to_str() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        // 首先检查进程的 uid
                        if let Ok(status) = std::fs::read_to_string(path.join("status")) {
                            if !status.lines().any(|line| {
                                line.starts_with("Uid:")
                                    && line.split_whitespace().nth(1).map_or(false, |real_uid| {
                                        real_uid
                                            .parse::<u32>()
                                            .map_or(false, |uid_val| uid_val == uid)
                                    })
                            }) {
                                continue;
                            }

                            // 检查是否有匹配的 socket inode
                            let fd_dir = path.join("fd");
                            if let Ok(fd_entries) = std::fs::read_dir(fd_dir) {
                                for fd_entry in fd_entries.filter_map(Result::ok) {
                                    if let Ok(target) = fd_entry.path().read_link() {
                                        if let Some(target_str) = target.to_str() {
                                            if target_str.contains(&format!("socket:[{}]", inode)) {
                                                return Some(pid);
                                            }
                                        }
                                    }
                                }
                            }

                            // 检查线程的文件描述符
                            let task_dir = path.join("task");
                            if let Ok(task_entries) = std::fs::read_dir(task_dir) {
                                for task_entry in task_entries.filter_map(Result::ok) {
                                    let fd_dir = task_entry.path().join("fd");
                                    if let Ok(fd_entries) = std::fs::read_dir(fd_dir) {
                                        for fd_entry in fd_entries.filter_map(Result::ok) {
                                            if let Ok(target) = fd_entry.path().read_link() {
                                                if let Some(target_str) = target.to_str() {
                                                    if target_str
                                                        .contains(&format!("socket:[{}]", inode))
                                                    {
                                                        return Some(pid);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}
