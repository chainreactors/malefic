use crate::win::common::to_wide_string;
use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use windows::core::{Error as WinError, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, FALSE,
    GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WIN32_ERROR,
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

pub struct NamedPipe {
    handle: HANDLE,
}

impl NamedPipe {
    // 创建命名管道
    pub fn create(pipe_name: &str) -> Result<Self, WIN32_ERROR> {
        let pipe_name_wide = to_wide_string(pipe_name);

        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(pipe_name_wide.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                512,  // 出站缓冲区大小
                512,  // 入站缓冲区大小
                0,    // 默认超时
                None, // 安全属性为None
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(WIN32_ERROR(unsafe { GetLastError().0 }));
        }

        Ok(NamedPipe { handle })
    }

    // 打开已有的命名管道
    pub fn open(pipe_name: &str) -> Result<Self, WIN32_ERROR> {
        let pipe_name_wide = to_wide_string(pipe_name);
        let handle = unsafe {
            CreateFileW(
                PCWSTR(pipe_name_wide.as_ptr()),
                PIPE_ACCESS_DUPLEX.0, // 读写访问
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED, // 使用重叠模式进行异步操作
                None,
            )
        };

        let handle = handle.map_err(|err| WIN32_ERROR(err.code().0 as u32))?; // Handle error here

        if handle == INVALID_HANDLE_VALUE {
            return Err(WIN32_ERROR(unsafe { GetLastError().0 }));
        }

        Ok(NamedPipe { handle })
    }

    // 等待客户端连接
    pub fn wait(&self) -> Result<(), WIN32_ERROR> {
        let result = unsafe { ConnectNamedPipe(self.handle, Some(null_mut())) };

        if result.is_err() {
            let error_code = unsafe { GetLastError().0 };
            if error_code != ERROR_PIPE_CONNECTED.0 {
                // Using the predefined error constant
                return Err(WIN32_ERROR(error_code));
            }
        }

        Ok(())
    }

    pub fn disconnect(&self) -> Result<(), WIN32_ERROR> {
        let result = unsafe { DisconnectNamedPipe(self.handle) };
        if result.is_err() {
            return Err(WIN32_ERROR(unsafe { GetLastError().0 }));
        }
        Ok(())
    }

    // 读取数据
    pub fn read(&self, buffer: &mut [u8]) -> Result<u32, WIN32_ERROR> {
        let mut bytes_read: u32 = 0;
        let result = unsafe { ReadFile(self.handle, Some(buffer), Some(&mut bytes_read), None) };

        if result.is_err() {
            return Err(WIN32_ERROR(unsafe { GetLastError().0 }));
        }

        Ok(bytes_read)
    }

    // 写入数据
    pub fn write(&self, buffer: &[u8]) -> Result<u32, WIN32_ERROR> {
        let mut bytes_written: u32 = 0;
        let result =
            unsafe { WriteFile(self.handle, Some(buffer), Some(&mut bytes_written), None) };

        if result.is_err() {
            return Err(WIN32_ERROR(unsafe { GetLastError().0 }));
        }
        Ok(bytes_written)
    }

    // 关闭管道
    pub fn close(&self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        };
    }

    // 获取管道句柄
    pub fn get_handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for NamedPipe {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}

pub struct PipeClient {
    handle: Handle,
}
unsafe impl Sync for PipeClient {}
unsafe impl Send for PipeClient {}
impl PipeClient {
    pub fn create_file(name: &Vec<u16>, mode: u32) -> io::Result<HANDLE> {
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
            // debug!("[+] Success create file: {:?}", handle);
            if handle.is_ok() {
                return Ok(handle?);
            }
            // debug!("[-] Failed to create file: {:?}", handle);
            let err = unsafe { GetLastError() };
            // debug!("[+] Error code: {:?}", err);
            match err {
                ERROR_PIPE_BUSY => {
                    let _ = unsafe { WaitNamedPipeW(PCWSTR::from_raw(name.as_ptr()), 0) };
                }
                ERROR_ACCESS_DENIED => {
                    if mode == (GENERIC_READ.0 | GENERIC_WRITE.0) {
                        return PipeClient::create_file(
                            name,
                            GENERIC_READ.0 | FILE_WRITE_ATTRIBUTES.0,
                        );
                    }
                    if mode == (GENERIC_READ.0 | FILE_WRITE_ATTRIBUTES.0) {
                        return PipeClient::create_file(
                            name,
                            GENERIC_WRITE.0 | FILE_READ_ATTRIBUTES.0,
                        );
                    }
                    return Err(io::Error::last_os_error());
                }
                _ => {
                    // debug!("[-] Failed to create file: {:?}, mode: {:?}", err,mode);
                    return Err(io::Error::last_os_error());
                }
            }
        }
    }
    pub fn connect(name: &str) -> io::Result<PipeClient> {
        PipeClient::connect_ms(name, 0xFFFFFFFF)
    }
    pub fn connect_ms(name: &str, timeout: u32) -> io::Result<PipeClient> {
        let wide_pipe_name: Vec<u16> = OsStr::new(&name)
            .encode_wide()
            .chain(Some(0).into_iter())
            .collect();
        let mut waited = false;
        loop {
            match PipeClient::create_file(&wide_pipe_name, GENERIC_READ.0 | GENERIC_WRITE.0) {
                Ok(handle) => {
                    let result = unsafe {
                        let mode =
                            NAMED_PIPE_MODE(PIPE_TYPE_BYTE.0 | PIPE_READMODE_BYTE.0 | PIPE_WAIT.0);
                        let mode_ptr = Some(&mode as *const NAMED_PIPE_MODE);
                        SetNamedPipeHandleState(handle, mode_ptr, None, None)
                    };
                    if result.is_ok() {
                        return Ok(PipeClient {
                            handle: Handle { value: handle },
                            // ovl: Overlapped::new()?,
                            // read_timeout: None,
                            // write_timeout: None,
                        });
                    } else {
                        return Err(io::Error::last_os_error());
                    }
                }
                Err(err) => {
                    if err.raw_os_error().unwrap() == ERROR_PIPE_BUSY.0 as i32 {
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

    pub fn read(&self, buffer: &mut [u8]) -> Result<usize, WinError> {
        let mut bytes_read = 0;
        unsafe {
            ReadFile(self.handle.value, Some(buffer), Some(&mut bytes_read), None)
                .map_err(|e| e.code())?;

            Ok(bytes_read as usize)
        }
    }

    pub fn write(&self, buffer: &[u8]) -> Result<usize, WinError> {
        assert!(buffer.len() <= 0xFFFFFFFF);
        let mut bytes_written = 0;
        unsafe {
            WriteFile(
                self.handle.value,
                Some(buffer),
                Some(&mut bytes_written),
                None,
            )
            .map_err(|e| e.code())?;

            Ok(bytes_written as usize)
        }
    }
}

impl Drop for PipeClient {
    fn drop(&mut self) {
        unsafe {
            let _ = FlushFileBuffers(self.handle.value);
            let _ = DisconnectNamedPipe(self.handle.value);
        }
    }
}

pub struct AnonymousPipe {
    read_handle: HANDLE,
    write_handle: HANDLE,
}

impl AnonymousPipe {
    pub fn create() -> Result<Self, WIN32_ERROR> {
        let mut read_handle = HANDLE::default();
        let mut write_handle = HANDLE::default();
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: true.into(),
        };

        unsafe {
            if CreatePipe(&mut read_handle, &mut write_handle, Some(&mut sa), 0).is_err() {
                return Err(WIN32_ERROR(GetLastError().0));
            }
        }

        Ok(AnonymousPipe {
            read_handle,
            write_handle,
        })
    }

    pub fn read(&self) -> Result<String, WIN32_ERROR> {
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
                let error = unsafe { GetLastError().0 };
                if error == 109 {
                    // ERROR_BROKEN_PIPE
                    break;
                }
                return Err(WIN32_ERROR(error));
            }

            if bytes_read == 0 {
                break;
            }

            total_output.extend_from_slice(&buffer[..bytes_read as usize]);
        }

        Ok(String::from_utf8_lossy(&total_output).to_string())
    }

    pub fn write(&self, data: &[u8]) -> Result<u32, WIN32_ERROR> {
        let mut bytes_written = 0;
        unsafe {
            WriteFile(
                self.write_handle,
                Some(data),
                Some(&mut bytes_written),
                None,
            )
            .map_err(|_| WIN32_ERROR(GetLastError().0))?;
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
