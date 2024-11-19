use async_std::net::TcpStream;
use async_trait::async_trait;
use anyhow::Result;
use malefic_helper::debug;
use crate::transport::Client;
use crate::transport::conn::Transport;
use crate::transport::dialer::DialerExt;

#[async_trait]
impl DialerExt for Client {
    async fn connect(&mut self, addr: &str) -> Result<Transport> {
        debug!("[transport] Connecting to {}", addr);
        match TcpStream::connect(addr).await {
            Ok(stream) => Ok(Transport::new(stream)),
            Err(e) => {
                debug!("Failed to connect to {}: {:?}", addr, e);
                Err(e.into())
            }
        }
    }
}


