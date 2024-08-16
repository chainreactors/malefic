use std::sync::Arc;
use std::mem::size_of;
use async_std::io::BufReader;
use futures::{AsyncReadExt, AsyncWriteExt, FutureExt};
use async_std::net::TcpStream;
use async_std::task::sleep;
use async_std::sync::{RwLock, Mutex};
use std::time::Duration;
use super::ClientTrait;
use async_trait::async_trait;
use crate::debug;

// start(1), id(4), len(4), end(1)
pub static PROTO_LEN: u32 = 10;

#[derive(Clone)]
pub struct TcpLock {
    pub write_lock: Arc<Mutex<bool>>,
    pub read_lock: Arc<Mutex<bool>>,
}

impl TcpLock {
    pub async fn write_wait(&self) -> Result<(), ()> {
        loop {
            let lock_guard = self.write_lock.lock().await;
            if *lock_guard {
                return Ok(());
            }
            drop(lock_guard);
            sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn write_over(&self) {
        *self.write_lock.lock().await = true;
    }

    pub async fn read_wait(&self) -> Result<(), ()> {
        loop {
            let lock_guard = self.read_lock.lock().await;
            if *lock_guard {
                return Ok(());
            }
            drop(lock_guard);
            sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn read_over(&self) {
        *self.read_lock.lock().await = true;
    }
}

pub struct TcpClient {
    urls: Vec<(String, u16)>,
}

#[async_trait]
impl ClientTrait for TcpClient {
    type Config = Vec<(String, u16)>;

    fn new(config: Self::Config) -> Option<Self> {
        Some(TcpClient { urls: config })
    }

    fn set_ca(&mut self, _ca: Vec<u8>) {}

    async fn recv(&self) -> Vec<u8> {
        let mut tcp_stream = None;
        let mut data = Vec::new();

        for (url, port) in &self.urls {
            match TcpStream::connect((url.as_str(), *port)).await {
                Ok(stream) => {
                    tcp_stream = Some(stream);
                    break;
                }
                Err(_) => {
                    debug!("TcpClient::recv() connect error, ip {}, port {}", url, port);
                    continue;
                }
            }
        }

        let mut tcp_stream = match tcp_stream {
            Some(stream) => stream,
            None => return data,
        };

        loop {
            let mut buf = vec![0; 1024];
            match tcp_stream.read(&mut buf).await {
                Ok(_) => {
                    debug!("TcpClient::recv() read succ");
                    data.extend(buf);
                }
                Err(_) => {
                    debug!("TcpClient::recv() read error");
                    return data;
                }
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    async fn send(&self, data: Vec<u8>) -> usize {
        let mut tcp_stream = None;

        for (url, port) in &self.urls {
            match TcpStream::connect((url.as_str(), *port)).await {
                Ok(stream) => {
                    tcp_stream = Some(stream);
                    break;
                }
                Err(_) => {
                    debug!("TcpClient::recv() connect error, ip {}, port {}", url, port);
                    continue;
                }
            }
        }

        let mut tcp_stream = match tcp_stream {
            Some(stream) => stream,
            None => return 0,
        };

        match tcp_stream.write(&data).await {
            Ok(len) => {
                debug!("TcpClient::send() write succ");
                len
            }
            Err(_) => {
                debug!("TcpClient::send() write error");
                0
            }
        }
    }

    async fn send_with_read(&self, data: Vec<u8>) -> Vec<u8> {
        let mut tcp_stream = None;

        for (url, port) in &self.urls {
            match TcpStream::connect((url.as_str(), *port)).await {
                Ok(stream) => {
                    tcp_stream = Some(stream);
                    break;
                }
                Err(_) => {
                    debug!("TcpClient::recv() connect error, ip {}, port {}", url, port);
                    continue;
                }
            }
        }

        let tcp_stream = match tcp_stream {
            Some(stream) => stream,
            None => return Vec::new(),
        };

        let send_over = Arc::new(RwLock::new(false));
        let tcp_lock = TcpLock {
            write_lock: Arc::new(Mutex::new(false)),
            read_lock: Arc::new(Mutex::new(false)),
        };

        let (reader, mut sender) = tcp_stream.split();
        let send_task = async {
            let split_len = data.len().min(9);
            let (head, tail) = data.split_at(split_len);

            if sender.write_all(head).await.is_err() {
                debug!("TcpClient::send_with_read() send error on head");
                *send_over.write().await = true;
                return;
            }

            sleep(Duration::from_millis(1000)).await;

            if sender.write_all(tail).await.is_err() {
                debug!("TcpClient::send_with_read() send error on tail");
                *send_over.write().await = true;
                return;
            }

            debug!("TcpClient::send_with_read() send success");

            if sender.flush().await.is_ok() {
                sleep(Duration::from_millis(1000)).await;
                tcp_lock.write_over().await;
                tcp_lock.read_wait().await.ok();
            }
        };

        let mut data: Vec<u8> = vec![];
        let peek_header_until_len = 4 + size_of::<u32>();
        let mut canary_data = vec![0; 1];
        let mut peek_data = vec![0; peek_header_until_len];
        let mut reader_buffer = BufReader::new(reader);

        let recv_task = async {
            let read_len = futures::select! {
                res = reader_buffer.read_exact(&mut canary_data).fuse() => {
                    if res.is_ok() {
                        let _ = reader_buffer.read_exact(&mut peek_data).await;
                        let len = u32::from_le_bytes(peek_data[4..8].try_into().unwrap_or_default());
                        debug!("header parse len is {}", len);
                        data.resize(1 + len as usize, 0);
                        let res = reader_buffer.read_exact(&mut data).await;
                        data = [&canary_data[..], &peek_data[..], &data[..]].concat();
                        res
                    } else {
                        res
                    }
                },
                _ = tcp_lock.write_wait().fuse() => Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof")),
            };

            if let Err(e) = read_len {
                debug!("TcpClient::send_with_read() recv error: {:?}", e);
            } else {
                debug!("TcpClient::send_with_read() recv success");
            }

            tcp_lock.read_over().await;
        };

        let (recv_result, _) = futures::join!(recv_task, send_task);
        debug!("recv result len: {:?}", recv_result);

        if data.len() == PROTO_LEN as usize {
            return Vec::new();
        }

        data
    }
}
