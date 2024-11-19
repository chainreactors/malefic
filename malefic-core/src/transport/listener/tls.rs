// use async_std::net::{TcpListener, TcpStream};
// use async_tls::TlsAcceptor;
// use async_trait::async_trait;
// use anyhow::Result;
// use crate::transport::conn::tls::TlsTransport;
// use crate::transport::listener::ListenerExt;
// 
// pub struct TlsListenerExt {
//     listener: TcpListener,
//     tls_acceptor: TlsAcceptor,
// }
// 
// #[async_trait]
// impl ListenerExt for TlsListenerExt {
//     async fn bind(addr: &str) -> Result<Self> {
//         let listener = TcpListener::bind(addr).await?;
//         let tls_acceptor = TlsAcceptor::default(); 
//         Ok(TlsListenerExt { listener, tls_acceptor })
//     }
// 
//     async fn accept(&mut self) -> Result<TlsTransport> {
//         let (stream, _addr) = self.listener.accept().await?;
//         let ca_cert = vec![]; // 放置 CA 证书
//         let domain = "localhost".to_string(); // 或从请求中获取域名
//         let tls_stream = self.tls_acceptor.accept(stream.clone()).await?;
//         Ok(TlsTransport{
//             inner_transport: stream,
//             tls_stream: Some(tls_stream),
//             ca: ca_cert,
//             domain,
//         })
//     }
// }
