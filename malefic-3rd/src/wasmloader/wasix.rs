use super::wasi::{
    checked_range, checked_range_u32, memory, read_u32, result_errno, write_u32_data, WasiState,
    ERRNO_AGAIN, ERRNO_BADF, ERRNO_FAULT, ERRNO_INVAL, ERRNO_IO, ERRNO_SUCCESS,
};
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use wasmi::errors::LinkerError;
use wasmi::{AsContext, AsContextMut, Caller, Linker};

const ADDRESS_SIZE: usize = 18;
const ADDRESS_PORT_SIZE: usize = 20;
const IOV_SIZE: usize = 8;
const ADDRESS_FAMILY_INET4: u8 = 1;
const SOCKET_TYPE_STREAM: i32 = 1;
const SOCKET_PROTOCOL_TCP: i32 = 6;
const FD_FLAG_NONBLOCK: i32 = 1 << 2;
const RECV_FLAG_PEEK: i32 = 1;
const MAX_HOST_SLEEP: std::time::Duration = std::time::Duration::from_secs(1);

enum SocketEntry {
    Pending { nonblocking: bool },
    Stream(TcpStream),
    Listener(TcpListener),
}

pub(super) struct SocketState {
    entries: HashMap<i32, SocketEntry>,
    next_fd: i32,
}

impl Default for SocketState {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            next_fd: 100,
        }
    }
}

impl SocketState {
    fn open(&mut self) -> i32 {
        let fd = self.next_fd;
        self.next_fd = self.next_fd.saturating_add(1);
        self.entries
            .insert(fd, SocketEntry::Pending { nonblocking: false });
        fd
    }

    pub(super) fn close(&mut self, fd: i32) -> bool {
        self.entries.remove(&fd).is_some()
    }

    pub(super) fn contains(&self, fd: i32) -> bool {
        self.entries.contains_key(&fd)
    }

    pub(super) fn poll_ready(&self, fd: i32, event_type: u8) -> bool {
        match self.entries.get(&fd) {
            Some(SocketEntry::Stream(stream)) if event_type == 1 => {
                let mut byte = [0u8; 1];
                match stream.peek(&mut byte) {
                    Ok(_) => true,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => false,
                    Err(_) => true,
                }
            }
            Some(SocketEntry::Stream(_)) if event_type == 2 => true,
            Some(SocketEntry::Listener(_)) => true,
            Some(SocketEntry::Pending { .. }) | None => false,
            Some(SocketEntry::Stream(_)) => false,
        }
    }

    pub(super) fn set_nonblocking(&mut self, fd: i32, enabled: bool) -> bool {
        match self.entries.get_mut(&fd) {
            Some(SocketEntry::Pending { nonblocking }) => {
                *nonblocking = enabled;
                true
            }
            Some(SocketEntry::Stream(stream)) => stream.set_nonblocking(enabled).is_ok(),
            Some(SocketEntry::Listener(listener)) => listener.set_nonblocking(enabled).is_ok(),
            None => false,
        }
    }
}

pub(super) fn register(linker: &mut Linker<WasiState>) -> Result<(), LinkerError> {
    linker.func_wrap(
        "wasix_32v1",
        "resolve",
        |mut caller: Caller<'_, WasiState>,
         host_ptr: i32,
         host_len: i32,
         port: i32,
         addresses_ptr: i32,
         address_count: i32,
         result_count_ptr: i32|
         -> i32 {
            resolve(
                &mut caller,
                host_ptr,
                host_len,
                port,
                addresses_ptr,
                address_count,
                result_count_ptr,
            )
        },
    )?;
    linker.func_wrap(
        "wasix_32v1",
        "sock_open",
        |mut caller: Caller<'_, WasiState>, family: i32, kind: i32, protocol: i32, fd_ptr: i32| {
            sock_open(&mut caller, family, kind, protocol, fd_ptr)
        },
    )?;
    linker.func_wrap(
        "wasix_32v1",
        "sock_connect",
        |mut caller: Caller<'_, WasiState>, fd: i32, address_ptr: i32| {
            sock_connect(&mut caller, fd, address_ptr)
        },
    )?;
    linker.func_wrap(
        "wasix_32v1",
        "sock_bind",
        |mut caller: Caller<'_, WasiState>, fd: i32, address_ptr: i32| {
            sock_bind(&mut caller, fd, address_ptr)
        },
    )?;
    linker.func_wrap(
        "wasix_32v1",
        "sock_listen",
        |caller: Caller<'_, WasiState>, fd: i32, _backlog: i32| {
            if matches!(
                caller.data().sockets.entries.get(&fd),
                Some(SocketEntry::Listener(_))
            ) {
                ERRNO_SUCCESS
            } else {
                ERRNO_BADF
            }
        },
    )?;
    linker.func_wrap(
        "wasix_32v1",
        "sock_accept_v2",
        |mut caller: Caller<'_, WasiState>,
         fd: i32,
         flags: i32,
         result_fd_ptr: i32,
         address_ptr: i32| {
            sock_accept(&mut caller, fd, flags, result_fd_ptr, address_ptr)
        },
    )?;
    linker.func_wrap(
        "wasix_32v1",
        "sock_send",
        |mut caller: Caller<'_, WasiState>,
         fd: i32,
         iovs_ptr: i32,
         iovs_len: i32,
         _flags: i32,
         written_ptr: i32| { sock_send(&mut caller, fd, iovs_ptr, iovs_len, written_ptr) },
    )?;
    linker.func_wrap(
        "wasix_32v1",
        "sock_recv",
        |mut caller: Caller<'_, WasiState>,
         fd: i32,
         iovs_ptr: i32,
         iovs_len: i32,
         flags: i32,
         read_ptr: i32,
         result_flags_ptr: i32| {
            sock_recv(
                &mut caller,
                fd,
                iovs_ptr,
                iovs_len,
                flags,
                read_ptr,
                result_flags_ptr,
            )
        },
    )?;
    linker.func_wrap(
        "wasix_32v1",
        "sock_set_opt_flag",
        |mut caller: Caller<'_, WasiState>, fd: i32, option: i32, enabled: i32| {
            let Some(SocketEntry::Stream(stream)) = caller.data_mut().sockets.entries.get_mut(&fd)
            else {
                return ERRNO_BADF;
            };
            match option {
                3 => result_errno(stream.set_nodelay(enabled != 0), ERRNO_IO),
                12 => ERRNO_SUCCESS,
                _ => ERRNO_SUCCESS,
            }
        },
    )?;
    linker.func_wrap(
        "wasix_32v1",
        "sock_shutdown",
        |caller: Caller<'_, WasiState>, fd: i32, how: i32| {
            let Some(SocketEntry::Stream(stream)) = caller.data().sockets.entries.get(&fd) else {
                return ERRNO_BADF;
            };
            let how = match how {
                1 => Shutdown::Read,
                2 => Shutdown::Write,
                _ => Shutdown::Both,
            };
            result_errno(stream.shutdown(how), ERRNO_IO)
        },
    )?;
    linker.func_wrap(
        "wasix_32v1",
        "thread_sleep",
        |_caller: Caller<'_, WasiState>, nanoseconds: i64| {
            if nanoseconds > 0 {
                std::thread::sleep(
                    std::time::Duration::from_nanos(nanoseconds as u64).min(MAX_HOST_SLEEP),
                );
            }
            ERRNO_SUCCESS
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_fdstat_set_flags",
        |mut caller: Caller<'_, WasiState>, fd: i32, flags: i32| {
            if caller
                .data_mut()
                .sockets
                .set_nonblocking(fd, flags & FD_FLAG_NONBLOCK != 0)
            {
                ERRNO_SUCCESS
            } else {
                ERRNO_BADF
            }
        },
    )?;
    Ok(())
}

fn resolve(
    caller: &mut Caller<'_, WasiState>,
    host_ptr: i32,
    host_len: i32,
    port: i32,
    addresses_ptr: i32,
    address_count: i32,
    result_count_ptr: i32,
) -> i32 {
    let Some(memory) = memory(caller) else {
        return ERRNO_FAULT;
    };
    let data = memory.data(caller.as_context());
    let Ok(host_range) = checked_range(host_ptr, host_len, data.len()) else {
        return ERRNO_FAULT;
    };
    let Ok(host) = std::str::from_utf8(&data[host_range]) else {
        return ERRNO_INVAL;
    };
    let Ok(capacity) = usize::try_from(address_count) else {
        return ERRNO_INVAL;
    };
    let Ok(port) = u16::try_from(port) else {
        return ERRNO_INVAL;
    };
    let Ok(addresses) = (host, port).to_socket_addrs() else {
        return ERRNO_IO;
    };
    let ipv4: Vec<Ipv4Addr> = addresses
        .filter_map(|address| match address.ip() {
            std::net::IpAddr::V4(address) => Some(address),
            std::net::IpAddr::V6(_) => None,
        })
        .take(capacity)
        .collect();

    let data = memory.data_mut(caller.as_context_mut());
    let Ok(start) = usize::try_from(addresses_ptr) else {
        return ERRNO_FAULT;
    };
    for (index, address) in ipv4.iter().enumerate() {
        let Some(offset) = start.checked_add(index.saturating_mul(ADDRESS_SIZE)) else {
            return ERRNO_FAULT;
        };
        if offset + ADDRESS_SIZE > data.len() {
            return ERRNO_FAULT;
        }
        data[offset..offset + ADDRESS_SIZE].fill(0);
        data[offset] = ADDRESS_FAMILY_INET4;
        data[offset + 2..offset + 6].copy_from_slice(&address.octets());
    }
    let Ok(count) = u32::try_from(ipv4.len()) else {
        return ERRNO_INVAL;
    };
    write_u32_data(data, result_count_ptr, count)
}

fn sock_open(
    caller: &mut Caller<'_, WasiState>,
    family: i32,
    kind: i32,
    protocol: i32,
    fd_ptr: i32,
) -> i32 {
    if family != ADDRESS_FAMILY_INET4 as i32
        || kind != SOCKET_TYPE_STREAM
        || protocol != SOCKET_PROTOCOL_TCP
    {
        return ERRNO_INVAL;
    }
    let Some(memory) = memory(caller) else {
        return ERRNO_FAULT;
    };
    let (data, state) = memory.data_and_store_mut(&mut *caller);
    let fd = state.sockets.open();
    write_u32_data(data, fd_ptr, fd as u32)
}

fn sock_connect(caller: &mut Caller<'_, WasiState>, fd: i32, address_ptr: i32) -> i32 {
    let Some(memory) = memory(caller) else {
        return ERRNO_FAULT;
    };
    let data = memory.data(caller.as_context());
    let Ok(address) = read_address(data, address_ptr) else {
        return ERRNO_FAULT;
    };
    let nonblocking = match caller.data().sockets.entries.get(&fd) {
        Some(SocketEntry::Pending { nonblocking }) => *nonblocking,
        Some(SocketEntry::Stream(_)) => return ERRNO_SUCCESS,
        _ => return ERRNO_BADF,
    };
    match TcpStream::connect(address) {
        Ok(stream) => {
            if stream.set_nonblocking(nonblocking).is_err() {
                return ERRNO_IO;
            }
            caller
                .data_mut()
                .sockets
                .entries
                .insert(fd, SocketEntry::Stream(stream));
            ERRNO_SUCCESS
        }
        Err(error) if error.kind() == ErrorKind::WouldBlock => super::wasi::ERRNO_INPROGRESS,
        Err(_) => ERRNO_IO,
    }
}

fn sock_bind(caller: &mut Caller<'_, WasiState>, fd: i32, address_ptr: i32) -> i32 {
    let Some(memory) = memory(caller) else {
        return ERRNO_FAULT;
    };
    let data = memory.data(caller.as_context());
    let Ok(address) = read_address(data, address_ptr) else {
        return ERRNO_FAULT;
    };
    let nonblocking = match caller.data().sockets.entries.get(&fd) {
        Some(SocketEntry::Pending { nonblocking }) => *nonblocking,
        _ => return ERRNO_BADF,
    };
    match TcpListener::bind(address) {
        Ok(listener) => {
            if listener.set_nonblocking(nonblocking).is_err() {
                return ERRNO_IO;
            }
            caller
                .data_mut()
                .sockets
                .entries
                .insert(fd, SocketEntry::Listener(listener));
            ERRNO_SUCCESS
        }
        Err(_) => ERRNO_IO,
    }
}

fn sock_accept(
    caller: &mut Caller<'_, WasiState>,
    fd: i32,
    flags: i32,
    result_fd_ptr: i32,
    address_ptr: i32,
) -> i32 {
    let result = {
        let Some(SocketEntry::Listener(listener)) = caller.data().sockets.entries.get(&fd) else {
            return ERRNO_BADF;
        };
        listener.accept()
    };
    let (stream, address) = match result {
        Ok(result) => result,
        Err(error) if error.kind() == ErrorKind::WouldBlock => return ERRNO_AGAIN,
        Err(_) => return ERRNO_IO,
    };
    if stream
        .set_nonblocking(flags & FD_FLAG_NONBLOCK != 0)
        .is_err()
    {
        return ERRNO_IO;
    }
    let new_fd = caller.data_mut().sockets.open();
    caller
        .data_mut()
        .sockets
        .entries
        .insert(new_fd, SocketEntry::Stream(stream));

    let Some(memory) = memory(caller) else {
        return ERRNO_FAULT;
    };
    let data = memory.data_mut(caller.as_context_mut());
    let result = write_u32_data(data, result_fd_ptr, new_fd as u32);
    if result != ERRNO_SUCCESS {
        return result;
    }
    write_address(data, address_ptr, address)
}

fn sock_send(
    caller: &mut Caller<'_, WasiState>,
    fd: i32,
    iovs_ptr: i32,
    iovs_len: i32,
    written_ptr: i32,
) -> i32 {
    let Some(memory) = memory(caller) else {
        return ERRNO_FAULT;
    };
    let (data, state) = memory.data_and_store_mut(&mut *caller);
    let Ok(iovs_len) = usize::try_from(iovs_len) else {
        return ERRNO_INVAL;
    };
    let mut payload = Vec::new();
    for index in 0..iovs_len {
        let Some(offset) = (iovs_ptr as usize).checked_add(index.saturating_mul(IOV_SIZE)) else {
            return ERRNO_FAULT;
        };
        let Ok(pointer) = read_u32(data, offset) else {
            return ERRNO_FAULT;
        };
        let Ok(length) = read_u32(data, offset + 4) else {
            return ERRNO_FAULT;
        };
        let Ok(range) = checked_range_u32(pointer, length, data.len()) else {
            return ERRNO_FAULT;
        };
        payload.extend_from_slice(&data[range]);
    }
    let Some(SocketEntry::Stream(stream)) = state.sockets.entries.get_mut(&fd) else {
        return ERRNO_BADF;
    };
    match stream.write(&payload) {
        Ok(written) => {
            let Ok(written) = u32::try_from(written) else {
                return ERRNO_INVAL;
            };
            write_u32_data(data, written_ptr, written)
        }
        Err(error) if error.kind() == ErrorKind::WouldBlock => ERRNO_AGAIN,
        Err(_) => ERRNO_IO,
    }
}

fn sock_recv(
    caller: &mut Caller<'_, WasiState>,
    fd: i32,
    iovs_ptr: i32,
    iovs_len: i32,
    flags: i32,
    read_ptr: i32,
    result_flags_ptr: i32,
) -> i32 {
    let Some(memory) = memory(caller) else {
        return ERRNO_FAULT;
    };
    let (data, state) = memory.data_and_store_mut(&mut *caller);
    let Ok(iovs_len) = usize::try_from(iovs_len) else {
        return ERRNO_INVAL;
    };
    let mut ranges = Vec::with_capacity(iovs_len);
    let mut capacity = 0usize;
    for index in 0..iovs_len {
        let Some(offset) = (iovs_ptr as usize).checked_add(index.saturating_mul(IOV_SIZE)) else {
            return ERRNO_FAULT;
        };
        let Ok(pointer) = read_u32(data, offset) else {
            return ERRNO_FAULT;
        };
        let Ok(length) = read_u32(data, offset + 4) else {
            return ERRNO_FAULT;
        };
        let Ok(range) = checked_range_u32(pointer, length, data.len()) else {
            return ERRNO_FAULT;
        };
        capacity = match capacity.checked_add(range.len()) {
            Some(capacity) => capacity,
            None => return ERRNO_INVAL,
        };
        ranges.push(range);
    }
    let Some(SocketEntry::Stream(stream)) = state.sockets.entries.get_mut(&fd) else {
        return ERRNO_BADF;
    };
    let mut buffer = vec![0u8; capacity];
    let result = if flags & RECV_FLAG_PEEK != 0 {
        stream.peek(&mut buffer)
    } else {
        stream.read(&mut buffer)
    };
    let read = match result {
        Ok(read) => read,
        Err(error) if error.kind() == ErrorKind::WouldBlock => return ERRNO_AGAIN,
        Err(_) => return ERRNO_IO,
    };
    let mut copied = 0usize;
    for range in ranges {
        let count = (read - copied).min(range.len());
        data[range.start..range.start + count].copy_from_slice(&buffer[copied..copied + count]);
        copied += count;
        if copied == read {
            break;
        }
    }
    let Ok(read) = u32::try_from(read) else {
        return ERRNO_INVAL;
    };
    let result = write_u32_data(data, read_ptr, read);
    if result != ERRNO_SUCCESS {
        return result;
    }
    write_u16_data(data, result_flags_ptr, 0)
}

fn read_address(data: &[u8], pointer: i32) -> Result<SocketAddr, ()> {
    let range = checked_range(pointer, ADDRESS_PORT_SIZE as i32, data.len())?;
    if data[range.start] != ADDRESS_FAMILY_INET4 {
        return Err(());
    }
    let port = u16::from_le_bytes([data[range.start + 2], data[range.start + 3]]);
    let ip = Ipv4Addr::new(
        data[range.start + 4],
        data[range.start + 5],
        data[range.start + 6],
        data[range.start + 7],
    );
    Ok(SocketAddr::from((ip, port)))
}

fn write_address(data: &mut [u8], pointer: i32, address: SocketAddr) -> i32 {
    let SocketAddr::V4(address) = address else {
        return ERRNO_INVAL;
    };
    let Ok(range) = checked_range(pointer, ADDRESS_PORT_SIZE as i32, data.len()) else {
        return ERRNO_FAULT;
    };
    data[range.clone()].fill(0);
    data[range.start] = ADDRESS_FAMILY_INET4;
    data[range.start + 2..range.start + 4].copy_from_slice(&address.port().to_le_bytes());
    data[range.start + 4..range.start + 8].copy_from_slice(&address.ip().octets());
    ERRNO_SUCCESS
}

fn write_u16_data(data: &mut [u8], pointer: i32, value: u16) -> i32 {
    let Ok(pointer) = usize::try_from(pointer) else {
        return ERRNO_FAULT;
    };
    let Some(destination) = data.get_mut(pointer..pointer + 2) else {
        return ERRNO_FAULT;
    };
    destination.copy_from_slice(&value.to_le_bytes());
    ERRNO_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_round_trip_uses_tinygo_layout() {
        let mut data = [0u8; ADDRESS_PORT_SIZE];
        let address: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(write_address(&mut data, 0, address), ERRNO_SUCCESS);
        assert_eq!(read_address(&data, 0).unwrap(), address);
    }
}
