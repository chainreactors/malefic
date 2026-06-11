use crate::common::{self, to_wide_string};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use windows::core::{Error, Result, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_PIPE_BUSY,
    ERROR_PIPE_CONNECTED, FALSE, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    WIN32_ERROR,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE,
    FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_ATTRIBUTES, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, CreatePipe, DisconnectNamedPipe, SetNamedPipeHandleState,
    WaitNamedPipeW, NAMED_PIPE_MODE, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_TYPE_MESSAGE,
    PIPE_WAIT,
};

const PIPE_UNLIMITED_INSTANCES: u32 = 255;
const PIPE_BUFFER_SIZE: u32 = 512;
const MAX_CREATE_FILE_RETRIES: u32 = 10;
const WAIT_NAMED_PIPE_TIMEOUT_MS: u32 = 5000;

#[derive(Debug)]
pub struct NamedPipe {
    handle: HANDLE,
}

impl NamedPipe {
    pub fn create(pipe_name: &str) -> Result<Self> {
        let pipe_name_wide = to_wide_string(pipe_name);
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(pipe_name_wide.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                0,
                None,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(common::last_win32_error());
        }
        Ok(NamedPipe { handle })
    }

    pub fn open(pipe_name: &str) -> Result<Self> {
        let pipe_name_wide = to_wide_string(pipe_name);
        let handle = unsafe {
            CreateFileW(
                PCWSTR(pipe_name_wide.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                None,
            )
        };
        let handle = handle?;
        if handle == INVALID_HANDLE_VALUE {
            return Err(common::last_win32_error());
        }
        Ok(NamedPipe { handle })
    }

    pub fn wait(&self) -> Result<()> {
        let result = unsafe { ConnectNamedPipe(self.handle, Some(null_mut())) };
        if result.is_err() {
            let error_code = unsafe { GetLastError().0 };
            if error_code != ERROR_PIPE_CONNECTED.0 {
                return Err(Error::from(WIN32_ERROR(error_code)));
            }
        }
        Ok(())
    }

    pub fn disconnect(&self) -> Result<()> {
        let result = unsafe { DisconnectNamedPipe(self.handle) };
        if result.is_err() {
            return Err(common::last_win32_error());
        }
        Ok(())
    }

    pub fn read(&self, buffer: &mut [u8]) -> Result<u32> {
        let mut bytes_read: u32 = 0;
        let result = unsafe { ReadFile(self.handle, Some(buffer), Some(&mut bytes_read), None) };
        if result.is_err() {
            return Err(common::last_win32_error());
        }
        Ok(bytes_read)
    }

    pub fn write(&self, buffer: &[u8]) -> Result<u32> {
        let mut bytes_written: u32 = 0;
        let result =
            unsafe { WriteFile(self.handle, Some(buffer), Some(&mut bytes_written), None) };
        if result.is_err() {
            return Err(common::last_win32_error());
        }
        Ok(bytes_written)
    }

    pub fn close(&mut self) {
        let _ = self.disconnect();
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
            self.handle = INVALID_HANDLE_VALUE;
        }
    }

    pub fn get_handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for NamedPipe {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            #[cfg(debug_assertions)]
            malefic_common::debug!("WARNING: NamedPipe dropped without close()");
            let _ = self.disconnect();
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

#[derive(Debug)]
struct Handle {
    value: HANDLE,
}

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.value) };
    }
}

unsafe impl Sync for Handle {}
unsafe impl Send for Handle {}

#[derive(Debug)]
pub struct PipeClient {
    handle: Handle,
}
unsafe impl Sync for PipeClient {}
unsafe impl Send for PipeClient {}

impl PipeClient {
    pub fn create_file(name: &[u16], initial_mode: u32) -> Result<HANDLE> {
        let access_modes = [
            initial_mode,
            GENERIC_READ.0 | FILE_WRITE_ATTRIBUTES.0,
            GENERIC_WRITE.0 | FILE_READ_ATTRIBUTES.0,
        ];

        for (idx, &mode) in access_modes.iter().enumerate() {
            // Only try fallback modes when the initial mode was full duplex
            if idx > 0 && initial_mode != (GENERIC_READ.0 | GENERIC_WRITE.0) {
                break;
            }

            let mut retries = 0;
            loop {
                let handle = unsafe {
                    CreateFileW(
                        PCWSTR::from_raw(name.as_ptr()),
                        mode,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        None,
                        OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED,
                        None,
                    )
                };
                match handle {
                    Ok(h) => return Ok(h),
                    Err(_) => {
                        let err = unsafe { GetLastError() };
                        match err {
                            ERROR_PIPE_BUSY => {
                                retries += 1;
                                if retries >= MAX_CREATE_FILE_RETRIES {
                                    break; // try next access mode
                                }
                                let _ = unsafe {
                                    WaitNamedPipeW(
                                        PCWSTR::from_raw(name.as_ptr()),
                                        WAIT_NAMED_PIPE_TIMEOUT_MS,
                                    )
                                };
                            }
                            ERROR_ACCESS_DENIED if idx < access_modes.len() - 1 => break,
                            _ => return Err(Error::from(WIN32_ERROR(err.0))),
                        }
                    }
                }
            }
        }
        Err(Error::from(WIN32_ERROR(ERROR_ACCESS_DENIED.0)))
    }

    pub fn connect(name: &str) -> Result<PipeClient> {
        PipeClient::connect_ms(name, 0xFFFFFFFF)
    }

    pub fn connect_ms(name: &str, timeout: u32) -> Result<PipeClient> {
        let wide_pipe_name: Vec<u16> = OsStr::new(&name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut waited = false;
        loop {
            match PipeClient::create_file(&wide_pipe_name, GENERIC_READ.0 | GENERIC_WRITE.0) {
                Ok(handle) => {
                    let result = unsafe {
                        let mode =
                            NAMED_PIPE_MODE(PIPE_TYPE_BYTE.0 | PIPE_READMODE_BYTE.0 | PIPE_WAIT.0);
                        SetNamedPipeHandleState(
                            handle,
                            Some(&mode as *const NAMED_PIPE_MODE),
                            None,
                            None,
                        )
                    };
                    if result.is_ok() {
                        return Ok(PipeClient {
                            handle: Handle { value: handle },
                        });
                    } else {
                        return Err(common::last_win32_error());
                    }
                }
                Err(err) => {
                    if err.code() == windows::core::HRESULT::from_win32(ERROR_PIPE_BUSY.0) {
                        if !waited {
                            waited = true;
                            let result =
                                unsafe { WaitNamedPipeW(PCWSTR(wide_pipe_name.as_ptr()), timeout) };
                            if result == FALSE {
                                return Err(err);
                            }
                        } else {
                            return Err(err);
                        }
                    } else {
                        return Err(err);
                    }
                }
            }
        }
    }

    pub fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        let mut bytes_read = 0;
        unsafe {
            ReadFile(self.handle.value, Some(buffer), Some(&mut bytes_read), None)?;
            Ok(bytes_read as usize)
        }
    }

    pub fn write(&self, buffer: &[u8]) -> Result<usize> {
        let mut bytes_written = 0;
        unsafe {
            WriteFile(
                self.handle.value,
                Some(buffer),
                Some(&mut bytes_written),
                None,
            )?;
            Ok(bytes_written as usize)
        }
    }
}

impl Drop for PipeClient {
    fn drop(&mut self) {
        unsafe {
            let _ = FlushFileBuffers(self.handle.value);
            // Note: DisconnectNamedPipe is a server-only API, not called here
        }
    }
}

#[derive(Debug)]
pub struct AnonymousPipe {
    read_handle: HANDLE,
    write_handle: HANDLE,
}

impl AnonymousPipe {
    pub fn create() -> Result<Self> {
        let mut read_handle = HANDLE::default();
        let mut write_handle = HANDLE::default();
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: true.into(),
        };
        unsafe {
            if CreatePipe(&mut read_handle, &mut write_handle, Some(&mut sa), 0).is_err() {
                return Err(common::last_win32_error());
            }
        }
        Ok(AnonymousPipe {
            read_handle,
            write_handle,
        })
    }

    pub fn read(&self) -> Result<String> {
        let mut buffer = [0u8; 4096];
        let mut total_output = Vec::new();
        loop {
            let mut bytes_read = 0;
            let result = unsafe {
                ReadFile(
                    self.read_handle,
                    Some(&mut buffer),
                    Some(&mut bytes_read),
                    None,
                )
            };
            if result.is_err() {
                let error = unsafe { GetLastError() };
                if error == ERROR_BROKEN_PIPE {
                    break;
                }
                return Err(Error::from(WIN32_ERROR(error.0)));
            }
            if bytes_read == 0 {
                break;
            }
            total_output.extend_from_slice(&buffer[..bytes_read as usize]);
        }
        Ok(String::from_utf8_lossy(&total_output).to_string())
    }

    pub fn write(&self, data: &[u8]) -> Result<u32> {
        let mut bytes_written = 0;
        unsafe {
            WriteFile(
                self.write_handle,
                Some(data),
                Some(&mut bytes_written),
                None,
            )?;
        }
        Ok(bytes_written)
    }

    pub fn get_read_handle(&self) -> HANDLE {
        self.read_handle
    }
    pub fn get_write_handle(&self) -> HANDLE {
        self.write_handle
    }
}

impl Drop for AnonymousPipe {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.read_handle);
            let _ = CloseHandle(self.write_handle);
        }
    }
}
