use std::{
    result,
    pin::Pin,
};
use std::io::Error;
use std::task::{Context, Poll};
use async_net::TcpStream;
use anyhow::Result;
use futures::{AsyncRead, AsyncWrite};
use async_trait::async_trait;
use crate::transport::proxie::{
    target::ToTarget,
};

#[async_trait]
pub trait AsyncProxy {
    async fn connect(&self, addr: impl ToTarget + Send) -> Result<ProxyTcpStream>;
}

pub struct ProxyTcpStream {
    pub(crate) stream: TcpStream,
}

impl ProxyTcpStream {
    pub fn into_tcpstream(self) -> TcpStream {
        self.stream
    }
}

impl AsyncRead for ProxyTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8]
    ) -> Poll<result::Result<usize, Error>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

// impl AsyncRead for &ProxyTcpStream {
//     fn poll_read(
//         self: Pin<&mut Self>,
//         cx: &mut Context<'_>,
//         buf: &mut [u8]
//     ) -> Poll<result::Result<usize, Error>> {
//         Pin::new(&mut self.stream).poll_read(cx, buf)
//     }
// }

impl AsyncWrite for ProxyTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8]
    ) -> Poll<result::Result<usize, Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<result::Result<(), Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<result::Result<(), Error>> {
        Pin::new(&mut self.stream).poll_close(cx)
    }
}

// impl AsyncWrite for &ProxyTcpStream {
//     fn poll_write(
//         self: Pin<&mut Self>,
//         cx: &mut Context<'_>,
//         buf: &[u8]
//     ) -> Poll<result::Result<usize, Error>> {
//         Pin::new(&mut &self.stream).poll_write(cx, buf)
//     }
// 
//     fn poll_flush(
//         self: Pin<&mut Self>,
//         cx: &mut Context<'_>
//     ) -> Poll<result::Result<(), Error>> {
//         Pin::new(&mut &self.stream).poll_flush(cx)
//     }
// 
//     fn poll_close(
//         self: Pin<&mut Self>,
//         cx: &mut Context<'_>
//     ) -> Poll<result::Result<(), Error>> {
//         Pin::new(&mut &self.stream).poll_close(cx)
//     }
// }

#[derive(Clone)]
pub struct Auth {
    pub(crate) username: String,
    pub(crate) password: String,
}

impl Auth {
    pub fn new(username: &str, password: &str) -> Option<Self> {
        if username == "" {
            return None
        }
        Some(Self {
            username: String::from(username),
            password: String::from(password),
        })
    }
}

#[derive(Clone)]
pub enum Proxy {
    HTTP(HTTPProxy),
    SOCKS5(SOCKS5Proxy),
}

#[derive(Clone)]
pub struct HTTPProxy {
    pub(crate) server: String,
    pub(crate) port: u16,
    pub(crate) auth: Option<Auth>,
}

impl HTTPProxy {
    pub fn new<T: Into<Option<Auth>>>(server: &str, port: u16, auth: T) -> Self {
        let auth = auth.into();
        Self {
            server: server.into(),
            port,
            auth,
        }
    }
}

#[derive(Clone)]
pub struct SOCKS5Proxy {
    pub(crate) server: String,
    pub(crate) port: u16,
    pub(crate) auth: Option<Auth>,
}

impl SOCKS5Proxy {
    pub fn new<T: Into<Option<Auth>>>(server: &str, port: u16, auth: T) -> Self {
        let auth = auth.into();
        Self {
            server: server.into(),
            port,
            auth,
        }
    }
}

pub(crate) enum SOCKS5Command {
    CONNECT,
}
