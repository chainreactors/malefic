use std::ptr::null_mut;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{GetLastError, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WIN32_ERROR};
use windows::Win32::Storage::FileSystem::{CreateFileW, ReadFile, WriteFile, 
                                          FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, 
                                          OPEN_EXISTING, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, ConnectNamedPipe, DisconnectNamedPipe,
    PIPE_TYPE_MESSAGE, PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
};
use crate::win::common::to_wide_string;

pub struct NamedPipe {
    pub handle: HANDLE,
}

unsafe impl Send for NamedPipe {}

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
                    512, // 出站缓冲区大小
                    512, // 入站缓冲区大小
                    0,   // 默认超时
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

        let handle = handle.map_err(|err| WIN32_ERROR(err.code().0 as u32))?;  // Handle error here

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
            if error_code != ERROR_PIPE_CONNECTED.0 { // Using the predefined error constant
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
        let result = unsafe {
            ReadFile(
                self.handle,
                Some(buffer),
                Some(&mut bytes_read),
                None,
            )
        };

        if result.is_err() {
            return Err(WIN32_ERROR(unsafe { GetLastError().0 }));
        }

        Ok(bytes_read)
    }

    // 写入数据
    pub fn write(&self, buffer: &[u8]) -> Result<u32, WIN32_ERROR> {
        let mut bytes_written: u32 = 0;
        let result = unsafe {
            WriteFile(
                self.handle,
                Some(buffer),
                Some(&mut bytes_written),
                None,
            )
        };
        
        if result.is_err() {
            return Err(WIN32_ERROR(unsafe { GetLastError().0 }));
        }
        Ok(bytes_written)
    }

    // 关闭管道
    pub fn close(&self) {
        unsafe { let _ = windows::Win32::Foundation::CloseHandle(self.handle); };
    }
}

impl Drop for NamedPipe {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}