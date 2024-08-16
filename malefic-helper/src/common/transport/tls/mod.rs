use async_std::io::BufReader;
use async_std::io::WriteExt;
use async_std::net::TcpStream;
use async_std::sync::RwLock;
use async_std::sync::Mutex;
use async_std::task::sleep;
use async_tls::TlsConnector;
use async_trait::async_trait;
use futures::AsyncReadExt;
use futures::FutureExt;
use rustls::{Certificate, ClientConfig, RootCertStore, ServerName};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::io::{Cursor, Error, ErrorKind};
use std::mem::size_of;
use std::sync::Arc;
use std::time::Duration;
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use crate::common::transport::tcp::TcpLock;
use crate::common::transport::tcp::PROTO_LEN;
use crate::debug;

use super::ClientTrait;

pub struct TlsClient {
    urls: Vec<(String, u16)>,
    ca: Option<Vec<u8>>,
}

#[async_trait]
impl ClientTrait for TlsClient {
    type Config = Vec<(String, u16)>;

    fn new(config: Self::Config) -> Option<Self> {
       Some(
            TlsClient {
                urls: config,
                ca: None,
            }
       )
    }

    fn set_ca(&mut self, ca: Vec<u8>) {
        self.ca = Some(ca);
    }

    async fn recv(&self) -> Vec<u8> {
        unimplemented!()
    }

    async fn send(&self, data: Vec<u8>) -> usize {
        let mut tcp_stream = None;
        let mut final_url = String::new();
        for (url, port) in &self.urls {
            match TcpStream::connect((url.as_str(), *port)).await {
                Ok(stream) => {
                    tcp_stream = Some(stream);
                    final_url = url.clone();
                    break;
                }
                Err(err) => {
                    debug!("TlsClient::recv() connect error, ip {}, port {}, {:#?}", url, port, err);
                    continue;
                }
            }
        }

        let mut tcp_stream = match tcp_stream {
            Some(stream) => stream,
            None => return 0,
        };
        debug!("{:#?}", self.ca);
        let tls_connector = match self.ca.clone() {
            Some(ca) => match connector_for_ca_file(ca).await {
                Ok(connector) => connector,
                Err(err) => {
                    debug!("{:#?}", err);
                    return 0
                },
            }
            None => TlsConnector::default(),
        };

        let mut tls_stream = match tls_connector.connect(final_url.as_str(), tcp_stream).await {
            Ok(stream) => stream,
            Err(err) => {
                debug!("{:#?}", err);
                return 0
            },
        };
        tls_stream.write(&data).await.unwrap_or_default()
    }

    async fn send_with_read(&self, data: Vec<u8>) -> Vec<u8> {
        let mut tcp_stream = None;
        let mut final_url = String::new();

        for (url, port) in &self.urls {
            match TcpStream::connect((url.as_str(), *port)).await {
                Ok(stream) => {
                    tcp_stream = Some(stream);
                    final_url = url.clone();
                    break;
                }
                Err(_) => {
                    debug!("TlsClient::recv() connect error, ip {}, port {}", url, port);
                    continue;
                }
            }
        }

        let mut tcp_stream = match tcp_stream {
            Some(stream) => stream,
            None => return Vec::new(),
        };
        let tls_connector = match self.ca.clone() {
            Some(ca) => match connector_for_ca_file(ca).await {
                Ok(connector) => connector,
                Err(_) => return Vec::new(),
            }
            None => TlsConnector::default(),
        };
        let tls_stream = match tls_connector.connect(final_url.as_str(), tcp_stream).await {
            Ok(stream) => stream,
            Err(_) => return Vec::new(),
        };
        let (reader, mut sender) = tls_stream.split();
        let send_over = Arc::new(RwLock::new(false));
        let tcp_lock = TcpLock {
            write_lock: Arc::new(Mutex::new(false)),
            read_lock: Arc::new(Mutex::new(false)),
        };

        let send_task = async {
            let split_len = data.len().min(9);
            let (head, tail) = data.split_at(split_len);

            if sender.write_all(head).await.is_err() {
                debug!("TlsCLient::send_with_read() send error on head");
                *send_over.write().await = true;
                return;
            }

            sleep(Duration::from_millis(1000)).await;

            if sender.write_all(tail).await.is_err() {
                debug!("TlsCLient::send_with_read() send error on tail");
                *send_over.write().await = true;
                return;
            }

            debug!("TlsCLient::send_with_read() send success");

            if sender.flush().await.is_ok() {
                sleep(Duration::from_millis(1000)).await;
                tcp_lock.write_over().await;
                tcp_lock.read_wait().await.ok();
            }
        };

        let mut data: Vec<u8> = vec![];
        let peek_header_until_len = 4 + size_of::<u32>();
        let mut canary_data = vec![0; 1];
        let mut peek_data = vec![0; peek_header_until_len];
        let mut reader_buffer = BufReader::new(reader);

        let recv_task = async {
            let read_len = futures::select! {
                res = reader_buffer.read_exact(&mut canary_data).fuse() => {
                    if res.is_ok() {
                        let _ = reader_buffer.read_exact(&mut peek_data).await;
                        let len = u32::from_le_bytes(peek_data[4..8].try_into().unwrap_or_default());
                        debug!("header parse len is {}", len);
                        data.resize(1 + len as usize, 0);
                        let res = reader_buffer.read_exact(&mut data).await;
                        data = [&canary_data[..], &peek_data[..], &data[..]].concat();
                        res
                    } else {
                        res
                    }
                },
                _ = tcp_lock.write_wait().fuse() => Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof")),
            };

            if let Err(e) = read_len {
                debug!("TlsCLient::send_with_read() recv error: {:?}", e);
            } else {
                debug!("TlsCLient::send_with_read() recv success");
            }

            tcp_lock.read_over().await;
        };

        let (recv_result, _) = futures::join!(recv_task, send_task);
        debug!("recv result len: {:?}", recv_result);

        if data.len() == PROTO_LEN as usize {
            return Vec::new();
        }

        data
    }
}

struct NoCertificateVerification;

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
        // 这里跳过证书验证，直接返回 Ok
        Ok(ServerCertVerified::assertion())
    }
}

async fn connector_for_ca_file(cafile: Vec<u8>) -> std::io::Result<TlsConnector> {
    let mut root_store = RootCertStore::empty();
    let cert = certs(&mut std::io::BufReader::new(Cursor::new(cafile))).unwrap();
    root_store.add_parsable_certificates(&cert);

    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.dangerous().set_certificate_verifier(Arc::new(NoCertificateVerification));

    let tls_conn: TlsConnector = TlsConnector::from(Arc::new(config));
    Ok(tls_conn)
}