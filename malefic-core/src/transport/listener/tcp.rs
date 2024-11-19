use async_std::net::{TcpListener};
use async_trait::async_trait;
use anyhow::Result;
use crate::transport::conn::tcp::TCPTransport;
use crate::transport::listener::ListenerExt;

pub struct TCPListenerExt {
    listener: TcpListener,
}

#[async_trait]
impl ListenerExt for TCPListenerExt {
    async fn bind(addr: &str) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(TCPListenerExt { listener })
    }
    
    async fn accept(&mut self) -> Result<TCPTransport> {
        let (stream, _addr) = self.listener.accept().await?;
        Ok(TCPTransport::new(stream))
    }
}