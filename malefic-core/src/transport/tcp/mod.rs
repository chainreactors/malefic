use std::pin::Pin;
use std::task::{Context, Poll};
use anyhow::Result;
use async_net::TcpStream;
use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::time::Duration;
use futures_timer::Delay;

use crate::transport::{DialerExt, Stream, TransportTrait};
#[cfg(feature = "proxy")]
use crate::config::{PROXY_HOST, PROXY_PASSWORD, PROXY_PORT, PROXY_USERNAME};
#[cfg(feature = "proxy")]
use crate::transport::proxie::{SOCKS5Proxy, AsyncProxy, Auth};

#[cfg(feature = "tls")]
use {
    async_tls::{client::TlsStream, TlsConnector},
    rustls::client::{ServerCertVerified, ServerCertVerifier, ServerName},
    rustls::{Certificate, ClientConfig, RootCertStore},
    rustls_pemfile::certs,
    std::sync::Arc,
};

pub struct TCPTransport {
    pub stream: TcpStream,
    #[cfg(feature = "tls")]
    tls_stream: Option<TlsStream<TcpStream>>,
    #[cfg(feature = "tls")]
    ca: Vec<u8>,
    #[cfg(feature = "tls")]
    domain: String,
}

impl Clone for TCPTransport {
    fn clone(&self) -> Self {
        TCPTransport {
            stream: self.stream.clone(),
            #[cfg(feature = "tls")]
            tls_stream: None,
            #[cfg(feature = "tls")]
            ca: self.ca.clone(),
            #[cfg(feature = "tls")]
            domain: self.domain.clone(),
        }
    }
}

impl TCPTransport {
    pub fn new(stream: TcpStream) -> Self {
        TCPTransport {
            stream,
            #[cfg(feature = "tls")]
            tls_stream: None,
            #[cfg(feature = "tls")]
            ca: Vec::new(),
            #[cfg(feature = "tls")]
            domain: String::new(),
        }
    }
    #[cfg(feature = "tls")]
    pub fn new_with_tls(stream: TcpStream, ca: Vec<u8>, domain: String) -> Self {
        TCPTransport {
            stream,
            tls_stream: None,
            ca,
            domain,
        }
    }

    #[cfg(feature = "tls")]
    pub fn new_connector(&self) -> Result<TlsConnector> {
        let mut root_store = RootCertStore::empty();
        let cert = certs(&mut std::io::BufReader::new(std::io::Cursor::new(&self.ca)))?;
        root_store.add_parsable_certificates(&cert);

        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification));

        let tls_conn: TlsConnector = TlsConnector::from(Arc::new(config));
        Ok(tls_conn)
    }

    #[cfg(feature = "tls")]
    pub async fn connect_tls(&mut self) -> Result<()> {
        let connector = self.new_connector()?;
        let tls_stream = connector
            .connect(self.domain.as_str(), self.stream.clone())
            .await?;
        self.tls_stream = Some(tls_stream);
        Ok(())
    }
}

impl AsyncRead for TCPTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        #[cfg(feature = "tls")]
        if let Some(ref mut tls_stream) = self.tls_stream {
            return Pin::new(tls_stream).poll_read(cx, buf);
        }

        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TCPTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        #[cfg(feature = "tls")]
        if let Some(ref mut tls_stream) = self.tls_stream {
            return Pin::new(tls_stream).poll_write(cx, buf);
        }

        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        #[cfg(feature = "tls")]
        if let Some(ref mut tls_stream) = self.tls_stream {
            return Pin::new(tls_stream).poll_flush(cx);
        }

        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        #[cfg(feature = "tls")]
        if let Some(ref mut tls_stream) = self.tls_stream {
            return Pin::new(tls_stream).poll_close(cx);
        }

        Pin::new(&mut self.stream).poll_close(cx)
    }
}


#[async_trait]
impl TransportTrait for TCPTransport {
    async fn done(&mut self) -> Result<()> {
        // default 500 ms ttl timeout
        Delay::new(Duration::from_millis(500)).await;
        Ok(())
    }
    async fn recv(&mut self, len: usize) -> Result<Vec<u8>> {
        #[cfg(feature = "tls")]
        if let Some(ref mut tls_stream) = self.tls_stream {
            let mut buf = vec![0; len];
            let n = tls_stream.read(&mut buf).await?;
            buf.truncate(n);
            return Ok(buf);
        }

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
        #[cfg(feature = "tls")]
        if let Some(ref mut tls_stream) = self.tls_stream {
            return Ok(tls_stream.write(&data).await?);
        }

        Ok(self.stream.write(&data).await?)
    }

    async fn close(&mut self) -> Result<bool> {
        #[cfg(feature = "tls")]
        if let Some(ref mut tls_stream) = self.tls_stream {
            tls_stream.get_mut().shutdown(std::net::Shutdown::Both)?;
            return Ok(true);
        }

        self.stream.shutdown(std::net::Shutdown::Both)?;
        Ok(true)
    }
}

#[cfg(feature = "tls")]
struct NoCertificateVerification;

#[cfg(feature = "tls")]
impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

#[derive(Clone)]
pub struct TCPClient {
    pub stream: Stream,
}

#[async_trait]
impl DialerExt for TCPClient {
    async fn connect(&mut self, addr: &str) -> Result<TCPTransport> {
        let tcp_stream: TcpStream = {
            #[cfg(all(feature = "proxy", feature = "socks5_proxy"))]
            {
                SOCKS5Proxy::new(&PROXY_HOST, PROXY_PORT.parse()?, Auth::new(&PROXY_USERNAME, &PROXY_PASSWORD))
                    .connect(addr)
                    .await?
                    .into_tcpstream()
            }
            #[cfg(all(feature = "proxy", feature = "http_proxy"))]
            {
                HTTPProxy::new(&PROXY_HOST, PROXY_PORT.parse()?, Auth::new(&PROXY_USERNAME, &PROXY_PASSWORD))
                    .connect(addr)
                    .await?
                    .into_tcpstream()
            }
            #[cfg(not(feature = "proxy"))]
            {
                TcpStream::connect(addr).await?
            }
        };

        #[cfg(feature = "tls")]
        if addr.starts_with("tls://") {
            let addr = addr.trim_start_matches("tls://");
            let ca_cert = vec![];
            let domain = addr.split(':').next().unwrap_or("").to_string();
            let mut transport = TCPTransport::new_with_tls(tcp_stream, ca_cert, domain);
            transport.connect_tls().await?;
            return Ok(transport);
        }

        Ok(TCPTransport::new(tcp_stream))
    }
}

#[cfg(feature = "bind")]
use crate::transport::ListenerExt;
#[cfg(feature = "bind")]
use async_net::TcpListener;


#[cfg(feature = "bind")]
pub struct TCPListenerExt {
    listener: TcpListener,
}

#[cfg(feature = "bind")]
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
