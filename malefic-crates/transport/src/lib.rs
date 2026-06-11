#![feature(io_error_more)]
#![feature(stmt_expr_attributes)]

#[cfg(feature = "transport_http")]
pub mod http;
#[cfg(feature = "transport_rem")]
pub mod rem;
#[cfg(feature = "tcp")]
pub mod tcp;

#[cfg(feature = "proxy")]
pub mod proxie;

pub mod connection;
pub mod runner;
pub mod server_manager;
pub mod session;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use malefic_crypto::crypto::CryptorError;
use std::io;
use thiserror::Error;

cfg_if::cfg_if! {
    if #[cfg(feature = "transport_tcp")] {
        pub use tcp::TCPTransport as InnerTransport;
        pub use tcp::TCPClient as Client;
    } else if #[cfg(feature = "transport_http")] {
        pub use http::HTTPTransport as InnerTransport;
        pub use http::HTTPClient as Client;
    } else if #[cfg(feature = "transport_rem")] {
        pub use rem::REMTransport as InnerTransport;
        pub use rem::REMClient as Client;
    } else {
        compile_error!("No transport selected");
    }
}

#[async_trait]
pub trait TransportImpl: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> TransportImpl for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

#[async_trait]
pub trait ListenerExt: Sized {
    async fn bind(addr: &str) -> anyhow::Result<Self>;
    async fn accept(&mut self) -> anyhow::Result<impl TransportImpl>;
}

#[async_trait]
pub trait DialerExt {
    async fn connect(
        &mut self,
        target: &crate::server_manager::Target,
    ) -> anyhow::Result<impl TransportImpl>;
}

#[cfg(feature = "bind")]
cfg_if::cfg_if! {
    if #[cfg(feature = "transport_tcp")] {
        pub use tcp::TCPListenerExt as Listener;
    } else {
        compile_error!("No transport selected");
    }
}

#[derive(Error, Debug)]
pub enum TransportError {
    #[error(transparent)]
    AnyHowError(#[from] anyhow::Error),

    #[error("Failed to connect to the server")]
    ConnectionError,

    #[error("Connection failed: {0}")]
    ConnectFailed(String),

    #[error("Configuration error")]
    ConfigurationError,

    #[error("Failed to encrypt/decrypt data")]
    CryptorError(#[from] CryptorError),

    #[error("Failed to send data")]
    SendError,

    #[error("Failed to send data within the timeout")]
    SendTimeout,

    #[error("Deadline")]
    Deadline,

    #[error("Connection refused")]
    ConnectionRefused,

    #[error("Connection reset")]
    ConnectionReset,

    #[error("Connection aborted")]
    ConnectionAborted,

    #[error("Network unreachable")]
    NetworkUnreachable,

    #[error("Other network error: {0}")]
    NetworkError(String),

    #[error("Failed to receive data")]
    RecvError,

    #[error("I/O Error: {0}")]
    IoError(#[from] io::Error),

    #[error("Parser error: {0}")]
    ParserError(#[from] malefic_proto::ParserError),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Unexpected end of stream")]
    UnexpectedEof,

    #[error("Unknown error occurred")]
    UnknownError,
}

impl TransportError {
    pub fn is_connection_error(&self) -> bool {
        match self {
            TransportError::ConnectionRefused
            | TransportError::ConnectionReset
            | TransportError::ConnectionAborted
            | TransportError::NetworkUnreachable => true,

            TransportError::IoError(e) => matches!(
                e.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::NetworkUnreachable
            ),

            _ => false,
        }
    }
}

pub use server_manager::{ServerManager, Target};

pub use session::{Session, SessionConfig, SessionReader, SessionWriter};

pub use connection::{
    create_connection, BuildError, Connection, ConnectionBuilder, ConnectionReader,
    ConnectionWriter,
};

pub use runner::ConnectionRunner;
