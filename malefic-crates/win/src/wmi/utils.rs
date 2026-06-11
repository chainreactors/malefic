use std::ffi::OsStr;
use std::fmt::Debug;
use std::os::windows::ffi::OsStrExt;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WMIError {
    /// You can find a useful resource for decoding error codes [here](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-error-constants)
    /// (or a github version [here](https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/WmiSdk/wmi-error-constants.md))
    #[error("HRESULT Call failed with: {hres:#X}")]
    HResultError { hres: i32 },
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error(transparent)]
    ParseFloatError(#[from] std::num::ParseFloatError),
    #[error("Converting from variant type {0:#X} is not implemented yet")]
    ConvertError(u16),
    #[error("{0}")]
    ConvertVariantError(String),
    #[error("Invalid bool value: {0:#X}")]
    ConvertBoolError(i16),
    #[error(transparent)]
    ConvertStringError(#[from] std::string::FromUtf16Error),
    #[error("Expected {0:?} to be at least 21 chars")]
    ConvertDatetimeError(String),
    #[error("Expected {0:?} to be at 25 chars")]
    ConvertDurationError(String),
    #[error("Length {0} was too long to convert")]
    ConvertLengthError(u64),
    #[error("{0}")]
    SerdeError(String),
    #[error("No results returned")]
    ResultEmpty,
    #[error("Null pointer was sent as part of query result")]
    NullPointerResult,
    #[error("Unimplemeted array item in query")]
    UnimplementedArrayItem,
    #[error("Invalid variant {0} during deserialization")]
    InvalidDeserializationVariantError(String),
}

impl From<windows::core::Error> for WMIError {
    fn from(value: windows::core::Error) -> Self {
        Self::HResultError {
            hres: value.code().0,
        }
    }
}

/// Alias type for `Result<T, WMIError>`
pub type WMIResult<T> = Result<T, WMIError>;

pub fn wide_rust_to_c_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
