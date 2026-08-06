use super::wasix::SocketState;
use std::ops::Range;
use std::time::{SystemTime, UNIX_EPOCH};
use wasmi::core::Trap;
use wasmi::errors::LinkerError;
use wasmi::{Caller, Linker, Memory, StoreLimits};

pub(super) const ERRNO_SUCCESS: i32 = 0;
pub(super) const ERRNO_AGAIN: i32 = 6;
pub(super) const ERRNO_BADF: i32 = 8;
pub(super) const ERRNO_FAULT: i32 = 21;
pub(super) const ERRNO_INPROGRESS: i32 = 26;
pub(super) const ERRNO_INVAL: i32 = 28;
pub(super) const ERRNO_IO: i32 = 29;
pub(super) const ERRNO_NOENT: i32 = 44;
pub(super) const ERRNO_NOSYS: i32 = 52;

const IOV_SIZE: usize = 8;
const SUBSCRIPTION_SIZE: usize = 48;
const EVENT_SIZE: usize = 32;
const MAX_HOST_SLEEP: std::time::Duration = std::time::Duration::from_secs(1);

pub(super) struct WasiState {
    args: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
    stdin: Vec<u8>,
    stdin_offset: usize,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
    pub(super) limits: StoreLimits,
    pub(super) sockets: SocketState,
    output_limit: usize,
}

impl WasiState {
    pub(super) fn new(
        program_name: String,
        args: Vec<String>,
        env: Vec<(String, String)>,
        stdin: Vec<u8>,
        limits: StoreLimits,
        output_limit: usize,
    ) -> Self {
        let args = std::iter::once(program_name)
            .chain(args)
            .map(String::into_bytes)
            .collect();
        let env = env
            .into_iter()
            .map(|(key, value)| format!("{key}={value}").into_bytes())
            .collect();
        Self {
            args,
            env,
            stdin,
            stdin_offset: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            limits,
            sockets: SocketState::default(),
            output_limit,
        }
    }
}

pub(super) fn register(linker: &mut Linker<WasiState>) -> Result<(), LinkerError> {
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_write",
        |mut caller: Caller<'_, WasiState>,
         fd: i32,
         iovs_ptr: i32,
         iovs_len: i32,
         written_ptr: i32|
         -> i32 { fd_write(&mut caller, fd, iovs_ptr, iovs_len, written_ptr) },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_read",
        |mut caller: Caller<'_, WasiState>,
         fd: i32,
         iovs_ptr: i32,
         iovs_len: i32,
         read_ptr: i32|
         -> i32 { fd_read(&mut caller, fd, iovs_ptr, iovs_len, read_ptr) },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "args_sizes_get",
        |mut caller: Caller<'_, WasiState>, count_ptr: i32, size_ptr: i32| -> i32 {
            vector_sizes(&mut caller, VectorKind::Args, count_ptr, size_ptr)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "args_get",
        |mut caller: Caller<'_, WasiState>, pointers: i32, buffer: i32| -> i32 {
            vector_get(&mut caller, VectorKind::Args, pointers, buffer)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "environ_sizes_get",
        |mut caller: Caller<'_, WasiState>, count_ptr: i32, size_ptr: i32| -> i32 {
            vector_sizes(&mut caller, VectorKind::Env, count_ptr, size_ptr)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "environ_get",
        |mut caller: Caller<'_, WasiState>, pointers: i32, buffer: i32| -> i32 {
            vector_get(&mut caller, VectorKind::Env, pointers, buffer)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "clock_time_get",
        |mut caller: Caller<'_, WasiState>, _clock: i32, _precision: i64, time_ptr: i32| -> i32 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            write_u64(&mut caller, time_ptr, nanos)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "clock_res_get",
        |mut caller: Caller<'_, WasiState>, _clock: i32, resolution_ptr: i32| -> i32 {
            write_u64(&mut caller, resolution_ptr, 1)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "random_get",
        |mut caller: Caller<'_, WasiState>, buffer_ptr: i32, buffer_len: i32| -> i32 {
            let Some(memory) = memory(&caller) else {
                return ERRNO_FAULT;
            };
            let data = memory.data_mut(&mut caller);
            let Ok(range) = checked_range(buffer_ptr, buffer_len, data.len()) else {
                return ERRNO_FAULT;
            };
            result_errno(getrandom::getrandom(&mut data[range]), ERRNO_IO)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "proc_exit",
        |_caller: Caller<'_, WasiState>, status: i32| -> Result<(), Trap> {
            Err(Trap::i32_exit(status))
        },
    )?;

    register_fd_metadata(linker)?;
    register_path_stubs(linker)?;
    register_poll(linker)?;
    Ok(())
}

fn fd_write(
    caller: &mut Caller<'_, WasiState>,
    fd: i32,
    iovs_ptr: i32,
    iovs_len: i32,
    written_ptr: i32,
) -> i32 {
    if fd != 1 && fd != 2 {
        return ERRNO_BADF;
    }
    let Some(memory) = memory(caller) else {
        return ERRNO_FAULT;
    };
    let (data, state) = memory.data_and_store_mut(&mut *caller);
    let Ok(iovs_len) = usize::try_from(iovs_len) else {
        return ERRNO_INVAL;
    };
    let mut total = 0usize;
    for index in 0..iovs_len {
        let Some(iov_offset) = (iovs_ptr as usize).checked_add(index.saturating_mul(IOV_SIZE))
        else {
            return ERRNO_FAULT;
        };
        let Ok(buffer_ptr) = read_u32(data, iov_offset) else {
            return ERRNO_FAULT;
        };
        let Ok(buffer_len) = read_u32(data, iov_offset + 4) else {
            return ERRNO_FAULT;
        };
        let Ok(range) = checked_range_u32(buffer_ptr, buffer_len, data.len()) else {
            return ERRNO_FAULT;
        };
        if !output_fits(
            state.stdout.len(),
            state.stderr.len(),
            range.len(),
            state.output_limit,
        ) {
            return ERRNO_IO;
        }
        if fd == 1 {
            state.stdout.extend_from_slice(&data[range.clone()]);
        } else {
            state.stderr.extend_from_slice(&data[range.clone()]);
        }
        total = match total.checked_add(range.len()) {
            Some(total) => total,
            None => return ERRNO_INVAL,
        };
    }
    let Ok(total) = u32::try_from(total) else {
        return ERRNO_INVAL;
    };
    write_u32_data(data, written_ptr, total)
}

fn output_fits(stdout: usize, stderr: usize, additional: usize, limit: usize) -> bool {
    stdout
        .checked_add(stderr)
        .and_then(|length| length.checked_add(additional))
        .map_or(false, |length| length <= limit)
}

fn fd_read(
    caller: &mut Caller<'_, WasiState>,
    fd: i32,
    iovs_ptr: i32,
    iovs_len: i32,
    read_ptr: i32,
) -> i32 {
    if fd != 0 {
        return ERRNO_BADF;
    }
    let Some(memory) = memory(caller) else {
        return ERRNO_FAULT;
    };
    let (data, state) = memory.data_and_store_mut(&mut *caller);
    let Ok(iovs_len) = usize::try_from(iovs_len) else {
        return ERRNO_INVAL;
    };
    let mut total = 0usize;
    for index in 0..iovs_len {
        let Some(iov_offset) = (iovs_ptr as usize).checked_add(index.saturating_mul(IOV_SIZE))
        else {
            return ERRNO_FAULT;
        };
        let Ok(buffer_ptr) = read_u32(data, iov_offset) else {
            return ERRNO_FAULT;
        };
        let Ok(buffer_len) = read_u32(data, iov_offset + 4) else {
            return ERRNO_FAULT;
        };
        let Ok(range) = checked_range_u32(buffer_ptr, buffer_len, data.len()) else {
            return ERRNO_FAULT;
        };
        let remaining = &state.stdin[state.stdin_offset..];
        let count = remaining.len().min(range.len());
        data[range.start..range.start + count].copy_from_slice(&remaining[..count]);
        state.stdin_offset += count;
        total += count;
        if count < range.len() {
            break;
        }
    }
    let Ok(total) = u32::try_from(total) else {
        return ERRNO_INVAL;
    };
    write_u32_data(data, read_ptr, total)
}

#[derive(Clone, Copy)]
enum VectorKind {
    Args,
    Env,
}

fn vector_sizes(
    caller: &mut Caller<'_, WasiState>,
    kind: VectorKind,
    count_ptr: i32,
    size_ptr: i32,
) -> i32 {
    let Some(memory) = memory(caller) else {
        return ERRNO_FAULT;
    };
    let (data, state) = memory.data_and_store_mut(&mut *caller);
    let values = vector(state, kind);
    let Ok(count) = u32::try_from(values.len()) else {
        return ERRNO_INVAL;
    };
    let size = values.iter().try_fold(0usize, |total, value| {
        total.checked_add(value.len().saturating_add(1))
    });
    let Some(size) = size.and_then(|size| u32::try_from(size).ok()) else {
        return ERRNO_INVAL;
    };
    let result = write_u32_data(data, count_ptr, count);
    if result != ERRNO_SUCCESS {
        return result;
    }
    write_u32_data(data, size_ptr, size)
}

fn vector_get(
    caller: &mut Caller<'_, WasiState>,
    kind: VectorKind,
    pointers_ptr: i32,
    buffer_ptr: i32,
) -> i32 {
    let Some(memory) = memory(caller) else {
        return ERRNO_FAULT;
    };
    let (data, state) = memory.data_and_store_mut(&mut *caller);
    let values = vector(state, kind);
    let Ok(mut cursor) = usize::try_from(buffer_ptr) else {
        return ERRNO_FAULT;
    };
    let Ok(pointers_start) = usize::try_from(pointers_ptr) else {
        return ERRNO_FAULT;
    };
    for (index, value) in values.iter().enumerate() {
        let Some(pointer_offset) = pointers_start.checked_add(index.saturating_mul(4)) else {
            return ERRNO_FAULT;
        };
        let Ok(cursor_u32) = u32::try_from(cursor) else {
            return ERRNO_FAULT;
        };
        if write_u32_at(data, pointer_offset, cursor_u32).is_err() {
            return ERRNO_FAULT;
        }
        let Some(end) = cursor.checked_add(value.len().saturating_add(1)) else {
            return ERRNO_FAULT;
        };
        if end > data.len() {
            return ERRNO_FAULT;
        }
        data[cursor..cursor + value.len()].copy_from_slice(value);
        data[cursor + value.len()] = 0;
        cursor = end;
    }
    ERRNO_SUCCESS
}

fn vector(state: &WasiState, kind: VectorKind) -> &[Vec<u8>] {
    match kind {
        VectorKind::Args => &state.args,
        VectorKind::Env => &state.env,
    }
}

fn register_fd_metadata(linker: &mut Linker<WasiState>) -> Result<(), LinkerError> {
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_close",
        |mut caller: Caller<'_, WasiState>, fd: i32| -> i32 {
            if (0..=2).contains(&fd) {
                ERRNO_SUCCESS
            } else if caller.data_mut().sockets.close(fd) {
                ERRNO_SUCCESS
            } else {
                ERRNO_BADF
            }
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_seek",
        |_caller: Caller<'_, WasiState>, _fd: i32, _offset: i64, _whence: i32, _new: i32| -> i32 {
            ERRNO_NOSYS
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_tell",
        |_caller: Caller<'_, WasiState>, _fd: i32, _offset: i32| -> i32 { ERRNO_NOSYS },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_sync",
        |_caller: Caller<'_, WasiState>, fd: i32| -> i32 {
            if (0..=2).contains(&fd) {
                ERRNO_SUCCESS
            } else {
                ERRNO_BADF
            }
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_fdstat_get",
        |mut caller: Caller<'_, WasiState>, fd: i32, buffer_ptr: i32| -> i32 {
            let file_type = if (0..=2).contains(&fd) {
                2
            } else if caller.data().sockets.contains(fd) {
                6
            } else {
                return ERRNO_BADF;
            };
            let Some(memory) = memory(&caller) else {
                return ERRNO_FAULT;
            };
            let data = memory.data_mut(&mut caller);
            let Ok(range) = checked_range(buffer_ptr, 24, data.len()) else {
                return ERRNO_FAULT;
            };
            data[range.clone()].fill(0);
            data[range.start] = file_type;
            let rights = 0x1FFF_FFFFu64.to_le_bytes();
            data[range.start + 8..range.start + 16].copy_from_slice(&rights);
            data[range.start + 16..range.start + 24].copy_from_slice(&rights);
            ERRNO_SUCCESS
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_filestat_get",
        |mut caller: Caller<'_, WasiState>, fd: i32, buffer_ptr: i32| -> i32 {
            let file_type = if (0..=2).contains(&fd) {
                2
            } else if caller.data().sockets.contains(fd) {
                6
            } else {
                return ERRNO_BADF;
            };
            let Some(memory) = memory(&caller) else {
                return ERRNO_FAULT;
            };
            let data = memory.data_mut(&mut caller);
            let Ok(range) = checked_range(buffer_ptr, 64, data.len()) else {
                return ERRNO_FAULT;
            };
            data[range.clone()].fill(0);
            data[range.start + 16] = file_type;
            ERRNO_SUCCESS
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_pread",
        |mut caller: Caller<'_, WasiState>,
         fd: i32,
         _iovs: i32,
         _iovs_len: i32,
         _offset: i64,
         read_ptr: i32|
         -> i32 {
            if fd != 0 {
                return ERRNO_BADF;
            }
            write_u32(&mut caller, read_ptr, 0)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_prestat_get",
        |_caller: Caller<'_, WasiState>, _fd: i32, _buffer: i32| -> i32 { ERRNO_BADF },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_prestat_dir_name",
        |_caller: Caller<'_, WasiState>, _fd: i32, _path: i32, _path_len: i32| -> i32 {
            ERRNO_BADF
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "sched_yield",
        |_caller: Caller<'_, WasiState>| -> i32 { ERRNO_SUCCESS },
    )?;
    Ok(())
}

fn register_path_stubs(linker: &mut Linker<WasiState>) -> Result<(), LinkerError> {
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "path_filestat_get",
        |_caller: Caller<'_, WasiState>,
         _fd: i32,
         _flags: i32,
         _path: i32,
         _path_len: i32,
         _buffer: i32|
         -> i32 { ERRNO_NOENT },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "path_open",
        |_caller: Caller<'_, WasiState>,
         _fd: i32,
         _dir_flags: i32,
         _path: i32,
         _path_len: i32,
         _open_flags: i32,
         _base_rights: i64,
         _inheriting_rights: i64,
         _fd_flags: i32,
         _opened_fd: i32|
         -> i32 { ERRNO_NOENT },
    )?;
    Ok(())
}

fn register_poll(linker: &mut Linker<WasiState>) -> Result<(), LinkerError> {
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "poll_oneoff",
        |mut caller: Caller<'_, WasiState>,
         input_ptr: i32,
         output_ptr: i32,
         subscriptions: i32,
         events_ptr: i32|
         -> i32 {
            let Ok(subscriptions) = usize::try_from(subscriptions) else {
                return ERRNO_INVAL;
            };
            let Some(memory) = memory(&caller) else {
                return ERRNO_FAULT;
            };
            let data = memory.data(&caller);
            let mut sleep_nanos = 0u64;
            let mut ready = Vec::new();
            for index in 0..subscriptions {
                let Some(offset) =
                    (input_ptr as usize).checked_add(index.saturating_mul(SUBSCRIPTION_SIZE))
                else {
                    return ERRNO_FAULT;
                };
                if offset + SUBSCRIPTION_SIZE > data.len() {
                    return ERRNO_FAULT;
                }
                let event_type = data[offset + 8];
                if event_type == 0 {
                    let Ok(timeout) = read_u64(data, offset + 24) else {
                        return ERRNO_FAULT;
                    };
                    sleep_nanos = sleep_nanos.max(timeout);
                } else {
                    let Ok(fd) = read_u32(data, offset + 16) else {
                        return ERRNO_FAULT;
                    };
                    if caller.data().sockets.poll_ready(fd as i32, event_type) {
                        ready.push(index);
                    }
                }
            }
            if ready.is_empty() && sleep_nanos > 0 {
                std::thread::sleep(
                    std::time::Duration::from_nanos(sleep_nanos).min(MAX_HOST_SLEEP),
                );
                ready.extend((0..subscriptions).filter(|index| {
                    let offset = input_ptr as usize + index * SUBSCRIPTION_SIZE;
                    data[offset + 8] == 0
                }));
            }

            let data = memory.data_mut(&mut caller);
            for (event_index, input_index) in ready.iter().copied().enumerate() {
                let input_offset = input_ptr as usize + input_index * SUBSCRIPTION_SIZE;
                let output_offset = output_ptr as usize + event_index * EVENT_SIZE;
                if input_offset + SUBSCRIPTION_SIZE > data.len()
                    || output_offset + EVENT_SIZE > data.len()
                {
                    return ERRNO_FAULT;
                }
                data[output_offset..output_offset + EVENT_SIZE].fill(0);
                let userdata = data[input_offset..input_offset + 8].to_vec();
                data[output_offset..output_offset + 8].copy_from_slice(&userdata);
                data[output_offset + 10] = data[input_offset + 8];
            }
            let Ok(events) = u32::try_from(ready.len()) else {
                return ERRNO_INVAL;
            };
            write_u32_data(data, events_ptr, events)
        },
    )?;
    Ok(())
}

pub(super) fn memory<T>(caller: &Caller<'_, T>) -> Option<Memory> {
    caller
        .get_export("memory")
        .and_then(|item| item.into_memory())
}

pub(super) fn checked_range(pointer: i32, length: i32, total: usize) -> Result<Range<usize>, ()> {
    let pointer = usize::try_from(pointer).map_err(|_| ())?;
    let length = usize::try_from(length).map_err(|_| ())?;
    let end = pointer.checked_add(length).ok_or(())?;
    if end > total {
        return Err(());
    }
    Ok(pointer..end)
}

pub(super) fn checked_range_u32(
    pointer: u32,
    length: u32,
    total: usize,
) -> Result<Range<usize>, ()> {
    let pointer = pointer as usize;
    let length = length as usize;
    let end = pointer.checked_add(length).ok_or(())?;
    if end > total {
        return Err(());
    }
    Ok(pointer..end)
}

pub(super) fn read_u32(data: &[u8], offset: usize) -> Result<u32, ()> {
    let bytes = data.get(offset..offset + 4).ok_or(())?;
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| ())?))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, ()> {
    let bytes = data.get(offset..offset + 8).ok_or(())?;
    Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| ())?))
}

fn write_u32(caller: &mut Caller<'_, WasiState>, pointer: i32, value: u32) -> i32 {
    let Some(memory) = memory(caller) else {
        return ERRNO_FAULT;
    };
    write_u32_data(memory.data_mut(caller), pointer, value)
}

pub(super) fn write_u32_data(data: &mut [u8], pointer: i32, value: u32) -> i32 {
    let Ok(pointer) = usize::try_from(pointer) else {
        return ERRNO_FAULT;
    };
    if write_u32_at(data, pointer, value).is_err() {
        return ERRNO_FAULT;
    }
    ERRNO_SUCCESS
}

pub(super) fn result_errno<T, E>(result: Result<T, E>, error: i32) -> i32 {
    match result {
        Ok(_) => ERRNO_SUCCESS,
        Err(_) => error,
    }
}

fn write_u32_at(data: &mut [u8], offset: usize, value: u32) -> Result<(), ()> {
    let destination = data.get_mut(offset..offset + 4).ok_or(())?;
    destination.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(caller: &mut Caller<'_, WasiState>, pointer: i32, value: u64) -> i32 {
    let Some(memory) = memory(caller) else {
        return ERRNO_FAULT;
    };
    let data = memory.data_mut(caller);
    let Ok(pointer) = usize::try_from(pointer) else {
        return ERRNO_FAULT;
    };
    let Some(destination) = data.get_mut(pointer..pointer + 8) else {
        return ERRNO_FAULT;
    };
    destination.copy_from_slice(&value.to_le_bytes());
    ERRNO_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_range_rejects_negative_and_overflowing_values() {
        assert!(checked_range(-1, 1, 16).is_err());
        assert!(checked_range(0, -1, 16).is_err());
        assert!(checked_range(12, 8, 16).is_err());
        assert_eq!(checked_range(4, 8, 16).unwrap(), 4..12);
    }

    #[test]
    fn output_limit_applies_to_both_streams() {
        assert!(output_fits(3, 4, 1, 8));
        assert!(!output_fits(3, 4, 2, 8));
        assert!(!output_fits(usize::MAX, 1, 0, usize::MAX));
    }

    #[test]
    fn result_errno_preserves_success_and_error() {
        assert_eq!(result_errno::<(), ()>(Ok(()), ERRNO_IO), ERRNO_SUCCESS);
        assert_eq!(result_errno::<(), ()>(Err(()), ERRNO_IO), ERRNO_IO);
    }
}
