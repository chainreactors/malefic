use std::io::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_CLASS, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_CLASS, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[derive(Clone)]
pub struct Socket {
    pub local_addr: String,
    pub remote_addr: String,
    pub protocol: String,
    pub pid: u32,
    pub state: String,
}

trait SocketTable {
    fn get_table() -> Result<Vec<u8>, Error>;
    fn get_rows_count(table: &[u8]) -> usize;
    fn get_socket_info(table: &[u8], index: usize) -> Socket;
}

#[allow(private_bounds)]
pub struct SocketTableIterator {
    table: Vec<u8>,
    rows_count: usize,
    current_row_index: usize,
    info_getter: fn(&[u8], usize) -> Socket,
}

impl SocketTableIterator {
    pub fn new<Table: SocketTable>() -> Result<Self, Error> {
        let table = Table::get_table()?;
        Ok(SocketTableIterator {
            rows_count: Table::get_rows_count(&table),
            info_getter: Table::get_socket_info,
            current_row_index: 0,
            table,
        })
    }
}

impl Iterator for SocketTableIterator {
    type Item = Result<Socket, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.current_row_index == self.rows_count {
            None
        } else {
            let socket_info = (self.info_getter)(&self.table, self.current_row_index);
            self.current_row_index += 1;
            Some(Ok(socket_info))
        }
    }
}

impl SocketTable for MIB_TCPTABLE_OWNER_PID {
    fn get_table() -> Result<Vec<u8>, Error> {
        get_extended_tcp_table(u32::from(AF_INET.0))
    }

    fn get_rows_count(table: &[u8]) -> usize {
        let table = unsafe { &*(table.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        table.dwNumEntries as usize
    }

    fn get_socket_info(table: &[u8], index: usize) -> Socket {
        let table = unsafe { &*(table.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let rows_ptr = &table.table[0] as *const MIB_TCPROW_OWNER_PID;
        let row = unsafe { &*rows_ptr.add(index) };
        Socket {
            local_addr: format!(
                "{}:{}",
                Ipv4Addr::from(u32::from_be(row.dwLocalAddr)),
                u16::from_be((row.dwLocalPort & 0xFFFF) as u16)
            ),
            remote_addr: format!(
                "{}:{}",
                Ipv4Addr::from(u32::from_be(row.dwRemoteAddr)),
                u16::from_be((row.dwRemotePort & 0xFFFF) as u16)
            ),
            protocol: "tcp".to_string(),
            pid: row.dwOwningPid,
            state: tcp_state_to_string(row.dwState),
        }
    }
}

impl SocketTable for MIB_TCP6TABLE_OWNER_PID {
    fn get_table() -> Result<Vec<u8>, Error> {
        get_extended_tcp_table(u32::from(AF_INET6.0))
    }

    fn get_rows_count(table: &[u8]) -> usize {
        let table = unsafe { &*(table.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
        table.dwNumEntries as usize
    }

    fn get_socket_info(table: &[u8], index: usize) -> Socket {
        let table = unsafe { &*(table.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
        let rows_ptr = &table.table[0] as *const MIB_TCP6ROW_OWNER_PID;
        let row = unsafe { &*rows_ptr.add(index) };
        Socket {
            local_addr: format!(
                "[{}]:{}",
                Ipv6Addr::from(row.ucLocalAddr),
                u16::from_be(row.dwLocalPort as u16)
            ),
            remote_addr: format!(
                "[{}]:{}",
                Ipv6Addr::from(row.ucRemoteAddr),
                u16::from_be(row.dwRemotePort as u16)
            ),
            protocol: "tcp6".to_string(),
            pid: row.dwOwningPid,
            state: tcp_state_to_string(row.dwState),
        }
    }
}

impl SocketTable for MIB_UDPTABLE_OWNER_PID {
    fn get_table() -> Result<Vec<u8>, Error> {
        get_extended_udp_table(u32::from(AF_INET.0))
    }

    fn get_rows_count(table: &[u8]) -> usize {
        let table = unsafe { &*(table.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        table.dwNumEntries as usize
    }

    fn get_socket_info(table: &[u8], index: usize) -> Socket {
        let table = unsafe { &*(table.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let rows_ptr = &table.table[0] as *const MIB_UDPROW_OWNER_PID;
        let row = unsafe { &*rows_ptr.add(index) };
        Socket {
            local_addr: format!(
                "{}:{}",
                Ipv4Addr::from(u32::from_be(row.dwLocalAddr)),
                u16::from_be((row.dwLocalPort & 0xFFFF) as u16)
            ),
            remote_addr: String::new(),
            protocol: "udp".to_string(),
            pid: row.dwOwningPid,
            state: String::new(),
        }
    }
}

impl SocketTable for MIB_UDP6TABLE_OWNER_PID {
    fn get_table() -> Result<Vec<u8>, Error> {
        get_extended_udp_table(u32::from(AF_INET6.0))
    }

    fn get_rows_count(table: &[u8]) -> usize {
        let table = unsafe { &*(table.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
        table.dwNumEntries as usize
    }

    fn get_socket_info(table: &[u8], index: usize) -> Socket {
        let table = unsafe { &*(table.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
        let rows_ptr = &table.table[0] as *const MIB_UDP6ROW_OWNER_PID;
        let row = unsafe { &*rows_ptr.add(index) };
        Socket {
            local_addr: format!(
                "[{}]:{}",
                Ipv6Addr::from(row.ucLocalAddr),
                u16::from_be(row.dwLocalPort as u16)
            ),
            remote_addr: String::new(),
            protocol: "udp6".to_string(),
            pid: row.dwOwningPid,
            state: String::new(),
        }
    }
}

pub fn get_sockets(ipv4: bool, ipv6: bool, tcp: bool, udp: bool) -> Result<Vec<Socket>, Error> {
    let mut sockets = Vec::new();

    if tcp {
        if ipv4 {
            sockets.extend(
                SocketTableIterator::new::<MIB_TCPTABLE_OWNER_PID>()?.filter_map(Result::ok),
            );
        }
        if ipv6 {
            sockets.extend(
                SocketTableIterator::new::<MIB_TCP6TABLE_OWNER_PID>()?.filter_map(Result::ok),
            );
        }
    }

    if udp {
        if ipv4 {
            sockets.extend(
                SocketTableIterator::new::<MIB_UDPTABLE_OWNER_PID>()?.filter_map(Result::ok),
            );
        }
        if ipv6 {
            sockets.extend(
                SocketTableIterator::new::<MIB_UDP6TABLE_OWNER_PID>()?.filter_map(Result::ok),
            );
        }
    }

    Ok(sockets)
}

fn get_extended_tcp_table(address_family: u32) -> Result<Vec<u8>, Error> {
    let mut table_size = 0;
    let mut err_code = unsafe {
        GetExtendedTcpTable(
            None,
            &mut table_size,
            false,
            address_family,
            TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL.0),
            0,
        )
    };

    let mut table = Vec::new();
    let mut iterations = 0;
    while err_code != ERROR_SUCCESS.0 && err_code == 122 {
        table = vec![0u8; table_size as usize];
        err_code = unsafe {
            GetExtendedTcpTable(
                Some(table.as_mut_ptr() as _),
                &mut table_size,
                false,
                address_family,
                TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL.0),
                0,
            )
        };
        iterations += 1;
        if iterations > 100 {
            return Err(Error::new(
                std::io::ErrorKind::Other,
                "Failed to allocate buffer",
            ));
        }
    }

    if err_code == ERROR_SUCCESS.0 {
        Ok(table)
    } else {
        Err(Error::last_os_error())
    }
}

fn get_extended_udp_table(address_family: u32) -> Result<Vec<u8>, Error> {
    let mut table_size = 0;
    let mut err_code = unsafe {
        GetExtendedUdpTable(
            None,
            &mut table_size,
            false,
            address_family,
            UDP_TABLE_CLASS(UDP_TABLE_OWNER_PID.0),
            0,
        )
    };

    let mut table = Vec::new();
    let mut iterations = 0;
    while err_code != ERROR_SUCCESS.0 && err_code == 122 {
        table = vec![0u8; table_size as usize];
        err_code = unsafe {
            GetExtendedUdpTable(
                Some(table.as_mut_ptr() as _),
                &mut table_size,
                false,
                address_family,
                UDP_TABLE_CLASS(UDP_TABLE_OWNER_PID.0),
                0,
            )
        };
        iterations += 1;
        if iterations > 100 {
            return Err(Error::new(
                std::io::ErrorKind::Other,
                "Failed to allocate buffer",
            ));
        }
    }

    if err_code == ERROR_SUCCESS.0 {
        Ok(table)
    } else {
        Err(Error::last_os_error())
    }
}

fn tcp_state_to_string(state: u32) -> String {
    match state {
        1 => "CLOSED".to_string(),
        2 => "LISTEN".to_string(),
        3 => "SYN_SENT".to_string(),
        4 => "SYN_RCVD".to_string(),
        5 => "ESTABLISHED".to_string(),
        6 => "FIN_WAIT1".to_string(),
        7 => "FIN_WAIT2".to_string(),
        8 => "CLOSE_WAIT".to_string(),
        9 => "CLOSING".to_string(),
        10 => "LAST_ACK".to_string(),
        11 => "TIME_WAIT".to_string(),
        12 => "DELETE_TCB".to_string(),
        _ => format!("UNKNOWN({})", state),
    }
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
