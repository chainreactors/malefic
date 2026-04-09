use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid PE file: {0}")]
    InvalidPe(String),

    #[error("File is not signed")]
    NotSigned,

    #[error("Invalid signature data")]
    #[allow(dead_code)]
    InvalidSignature,

    #[error("Parse error: {0}")]
    #[allow(dead_code)]
    Parse(String),

    #[error("Anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
}

#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, SignError>;
