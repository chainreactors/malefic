use async_tls::TlsConnector;
use rustls::{ClientConfig, RootCertStore, Certificate};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use async_std::net::TcpStream;
use async_trait::async_trait;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use anyhow::Result;
use crate::transport::{TransportTrait, TransportError};
use async_tls::client::TlsStream;
use rustls_pemfile::certs;
use rustls::client::{ServerName, ServerCertVerified, ServerCertVerifier};

pub struct TlsTransport {
    pub(crate) inner_transport: TcpStream,  // 使用 TCP 作为底层传输
    pub(crate) tls_stream: Option<TlsStream<TcpStream>>,  // TLS 封装后的流
    pub(crate) ca: Vec<u8>,
    pub(crate) domain: String,
}

impl TlsTransport {
    pub fn new(inner_transport: TcpStream, ca: Vec<u8>, domain: String) -> Self {
        TlsTransport {
            inner_transport,
            tls_stream: None,
            ca,
            domain,
        }
    }

    pub fn new_connector(&self) -> Result<TlsConnector> {
        let mut root_store = RootCertStore::empty();
        let cert = certs(&mut std::io::BufReader::new(std::io::Cursor::new(&self.ca)))?;
        root_store.add_parsable_certificates(&cert);

        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        config.dangerous().set_certificate_verifier(Arc::new(NoCertificateVerification));

        let tls_conn: TlsConnector = TlsConnector::from(Arc::new(config));
        Ok(tls_conn)
    }

    pub async fn connect_tls(&mut self) -> Result<(), TransportError> {
        let connector = self.new_connector().map_err(|_| TransportError::ConnectionError)?;
        let tls_stream = connector.connect(self.domain.as_str(), self.inner_transport.clone()).await.map_err(|_| TransportError::ConnectionError)?;
        self.tls_stream = Some(tls_stream);
        Ok(())
    }
}

#[async_trait]
impl TransportTrait for TlsTransport {
    async fn recv(&mut self, len: usize) -> Result<Vec<u8>> {
        if let Some(ref mut tls_stream) = self.tls_stream {
            let mut buf = vec![0; len];
            let n = tls_stream.read(&mut buf).await.map_err(|e| TransportError::IoError(e))?;
            buf.truncate(n);
            Ok(buf)
        } else {
            Err(TransportError::RecvError.into())
        }
    }

    async fn send(&mut self, data: Vec<u8>) -> Result<usize> {
        if let Some(ref mut tls_stream) = self.tls_stream {
            tls_stream.write(&data).await.map_err(|e| TransportError::IoError(e).into())
        } else {
            Err(TransportError::SendError.into())
        }
    }

    async fn close(&mut self) -> Result<bool> {
        if let Some(ref mut tls_stream) = self.tls_stream {
            tls_stream.get_mut().shutdown(async_std::net::Shutdown::Both)?;
        }
        Ok(true)
    }
}

// 为 TlsTransport 实现 AsyncRead
impl AsyncRead for TlsTransport {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, std::io::Error>> {
        if let Some(ref mut tls_stream) = self.tls_stream {
            Pin::new(tls_stream).poll_read(cx, buf)
        } else {
            Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "Not connected")))
        }
    }
}

// 为 TlsTransport 实现 AsyncWrite
impl AsyncWrite for TlsTransport {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        if let Some(ref mut tls_stream) = self.tls_stream {
            Pin::new(tls_stream).poll_write(cx, buf)
        } else {
            Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "Not connected")))
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        if let Some(ref mut tls_stream) = self.tls_stream {
            Pin::new(tls_stream).poll_flush(cx)
        } else {
            Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "Not connected")))
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        if let Some(ref mut tls_stream) = self.tls_stream {
            Pin::new(tls_stream).poll_close(cx)
        } else {
            Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "Not connected")))
        }
    }
}

struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(&self, _end_entity: &Certificate, _intermediates: &[Certificate], _server_name: &ServerName, _scts: &mut dyn Iterator<Item = &[u8]>, _ocsp_response: &[u8], _now: std::time::SystemTime) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}
