#![feature(offset_of)]
#![feature(stmt_expr_attributes)]
pub mod common;

#[cfg(target_os = "windows")]
pub mod win;

#[cfg(target_os = "macos")]
pub mod darwin;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux;

#[cfg(test)]
#[macro_use]
extern crate std;

pub use thiserror::Error;

#[macro_export]
macro_rules! to_error {
    ($expr:expr) => {
        $expr.map_err(|e| anyhow::Error::msg(format!("{:#?}", e)))
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            println!($($arg)*);
        }
    };
}

#[derive(Error, Debug)]
pub enum CommonError {
    #[error(transparent)]
    AnyError(#[from] anyhow::Error),

    #[error("{0}")]
    Win32Error(u32),

    #[error("")]
    AllocationFailed,

    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error("")]
    FreeFailed,

    #[error("")]
    NotImpl,

    #[error("{0}")]
    ArgsError(String),
}



pub struct Defer {
    #[allow(dead_code)]
    message: String,
}
impl Defer {
    pub fn new(message: &str) -> Self {
        Defer {
            message: message.to_string(),
        }
    }
}

impl Drop for Defer {
    fn drop(&mut self) {
        debug!("{}", self.message);
    }
}
