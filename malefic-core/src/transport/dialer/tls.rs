use async_std::net::TcpStream;
use async_trait::async_trait;
use anyhow::Result;
use crate::transport::conn::tls::TlsTransport;
use crate::transport::Client;
use crate::transport::dialer::DialerExt;

#[async_trait]
impl DialerExt for Client {
    async fn connect(&mut self, addr: &str) -> Result<TlsTransport> {
        let tcp_stream = TcpStream::connect(addr).await?;
        let ca_cert = vec![]; // 放置 CA 证书，您可以根据需要填充
        let domain = addr.split(':').next().unwrap_or("").to_string();
        Ok(TlsTransport::new(tcp_stream, ca_cert, domain))
    }
}
