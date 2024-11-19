use async_std::net::TcpStream;
use async_trait::async_trait;
use anyhow::Result;

#[derive(Clone)]
pub struct TCPTransport {
    stream: TcpStream,
}

impl TCPTransport {
    pub fn new(stream: TcpStream) -> Self {
        TCPTransport { stream }
    }
}

#[async_trait]
impl TransportTrait for TCPTransport {
    async fn recv(&mut self, len: usize) -> Result<Vec<u8>> {
        let max_buffer_size = 8192; 
        let buf_size = len.min(max_buffer_size);

        let mut buf = vec![0; buf_size];
        let mut result = Vec::new();
        
        while result.len() < len {
            let n = self.stream.read(&mut buf).await?;
            if n == 0 {
                break; 
            }
            result.extend_from_slice(&buf[..n]);
        }
        
        result.truncate(len);
        Ok(result)
    }

    async fn send(&mut self, data: Vec<u8>) -> Result<usize> {
        Ok(self.stream.write(&data).await?)
    }

    async fn close(&mut self) -> Result<bool> {
        self.stream.shutdown(async_std::net::Shutdown::Both)?;
        Ok(true)
    }
}


use async_std::io::{Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use futures::{AsyncReadExt, AsyncWriteExt};
use crate::transport::TransportTrait;

impl Read for TCPTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl Write for TCPTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_close(cx)
    }
}
