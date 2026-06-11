pub use thiserror::Error;

use malefic_gateway::obfstr::obfstr;
use std::time::{SystemTime, UNIX_EPOCH};

// ---- Utility macros ----

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
            println!(
                "[{}] {}",
                $crate::errors::debug_timestamp(),
                format_args!($($arg)*)
            );
        }
    };
}

pub fn debug_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let hours = (secs / 3600) % 24;
    let minutes = (secs / 60) % 60;
    let seconds = secs % 60;
    let millis = now.subsec_millis();
    format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis)
}

// ---- TaskError (moved from malefic-module) ----

#[derive(Debug)]
pub enum TaskError {
    OperatorError(anyhow::Error),
    NotExpectBody,
    FieldRequired { msg: String },
    FieldLengthMismatch { msg: String },
    FieldInvalid { msg: String },
    NotImpl,
}

impl std::fmt::Display for TaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskError::OperatorError(e) => std::fmt::Display::fmt(e, f),
            TaskError::NotExpectBody => f.write_str(obfstr!("task body was not expected")),
            TaskError::FieldRequired { msg } => f.write_str(msg),
            TaskError::FieldLengthMismatch { msg } => f.write_str(msg),
            TaskError::FieldInvalid { msg } => f.write_str(msg),
            TaskError::NotImpl => f.write_str(obfstr!("task not implemented")),
        }
    }
}

impl std::error::Error for TaskError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TaskError::OperatorError(e) => e.source(),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for TaskError {
    fn from(e: anyhow::Error) -> Self {
        TaskError::OperatorError(e)
    }
}

impl TaskError {
    pub fn id(&self) -> i32 {
        match self {
            TaskError::OperatorError { .. } => 2,
            TaskError::NotExpectBody => 3,
            TaskError::FieldRequired { .. } => 4,
            TaskError::FieldLengthMismatch { .. } => 5,
            TaskError::FieldInvalid { .. } => 6,
            TaskError::NotImpl => 99,
        }
    }
}

// ---- MaleficError (moved from error.rs) ----

#[derive(Debug)]
pub enum MaleficError {
    Panic(anyhow::Error),

    UnpackError,

    MissBody,

    UnExceptBody,

    ModuleError,

    ModuleNotFound,

    AddonNotFound,

    TaskError(TaskError),

    TransportError(String),

    TaskNotFound,

    TaskOperatorNotFound,

    /// Internal module that only makes sense in beacon/bind mode (not headless).
    BeaconOnly(String),
}

impl std::fmt::Display for MaleficError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MaleficError::Panic(e) => std::fmt::Display::fmt(e, f),
            MaleficError::UnpackError => f.write_str(obfstr!("failed to unpack data")),
            MaleficError::MissBody => f.write_str(obfstr!("expected body is missing")),
            MaleficError::UnExceptBody => f.write_str(obfstr!("unexpected body type")),
            MaleficError::ModuleError => f.write_str(obfstr!("module execution failed")),
            MaleficError::ModuleNotFound => f.write_str(obfstr!("module not found")),
            MaleficError::AddonNotFound => f.write_str(obfstr!("addon not found")),
            MaleficError::TaskError(e) => write!(f, "{}: {}", obfstr!("Task error"), e),
            MaleficError::TransportError(s) => write!(f, "{}: {}", obfstr!("Transport"), s),
            MaleficError::BeaconOnly(s) => write!(f, "{}: {}", obfstr!("beacon-only module"), s),
            MaleficError::TaskNotFound => f.write_str(obfstr!("task not found")),
            MaleficError::TaskOperatorNotFound => f.write_str(obfstr!("task operator not found")),
        }
    }
}

impl std::error::Error for MaleficError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MaleficError::Panic(e) => e.source(),
            MaleficError::TaskError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for MaleficError {
    fn from(e: anyhow::Error) -> Self {
        MaleficError::Panic(e)
    }
}

impl From<TaskError> for MaleficError {
    fn from(e: TaskError) -> Self {
        MaleficError::TaskError(e)
    }
}

impl MaleficError {
    pub fn id(&self) -> u32 {
        match self {
            MaleficError::Panic { .. } => 1,
            MaleficError::UnpackError => 2,
            MaleficError::MissBody => 3,
            MaleficError::ModuleError => 4,
            MaleficError::ModuleNotFound => 5,
            MaleficError::TaskError { .. } => 6,
            MaleficError::TaskNotFound => 7,
            MaleficError::TaskOperatorNotFound => 8,
            MaleficError::AddonNotFound => 9,
            MaleficError::UnExceptBody => 10,
            MaleficError::TransportError { .. } => 11,
            MaleficError::BeaconOnly { .. } => 12,
        }
    }
}

// ---- CommonError (moved from common_error.rs) ----

#[derive(Debug)]
pub enum CommonError {
    AnyError(anyhow::Error),

    Win32Error(u32),

    AllocationFailed,

    IOError(std::io::Error),

    FreeFailed,

    NotImpl,

    ArgsError(String),
}

impl std::fmt::Display for CommonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommonError::AnyError(e) => std::fmt::Display::fmt(e, f),
            CommonError::Win32Error(code) => write!(f, "{}", code),
            CommonError::AllocationFailed => f.write_str(obfstr!("memory allocation failed")),
            CommonError::IOError(e) => std::fmt::Display::fmt(e, f),
            CommonError::FreeFailed => f.write_str(obfstr!("memory free failed")),
            CommonError::NotImpl => f.write_str(obfstr!("not implemented")),
            CommonError::ArgsError(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for CommonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CommonError::AnyError(e) => e.source(),
            CommonError::IOError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for CommonError {
    fn from(e: anyhow::Error) -> Self {
        CommonError::AnyError(e)
    }
}

impl From<std::io::Error> for CommonError {
    fn from(e: std::io::Error) -> Self {
        CommonError::IOError(e)
    }
}

// ---- Defer ----

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

#[cfg(test)]
mod tests {
    use super::debug_timestamp;

    #[test]
    fn debug_timestamp_has_expected_shape() {
        let ts = debug_timestamp();
        assert_eq!(ts.len(), 12);
        assert_eq!(&ts[2..3], ":");
        assert_eq!(&ts[5..6], ":");
        assert_eq!(&ts[8..9], ".");
    }
}
