#[cfg(target_os = "windows")]
pub mod win;

pub mod common;

pub mod protobuf;

#[cfg(target_os = "macos")]
pub mod darwin;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_family = "unix")]
pub mod unix;

#[cfg(test)]
#[macro_use]
extern crate std;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommonError {
    #[cfg(target_os = "windows")]
    #[error(transparent)]
    WinApiError(#[from] windows::core::Error),

    #[error(transparent)]
    NetstatError(#[from] netstat2::error::Error),

    #[error("{0}")]
    Win32Error(u32),

    #[error("")]
    AllocationFailed,

    #[error(transparent)]
    UnixError(#[from] std::io::Error),

    #[error("")]
    FreeFailed,

    #[error("")]
    NotImpl,

    #[error("{0}")]
    ArgsError(String),
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            println!($($arg)*);
        }
    };
}
