use std::future::Future;
use crate::transport::{DialerExt, Stream};
use crate::common::spawn_blocking;
use anyhow::Result;
use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use malefic_helper::common::rem;
use malefic_helper::debug;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use malefic_proto::crypto::Cryptor;

pub struct REMTransport {
    handle: i32,
    buffer: Vec<u8>,
    buffer_pos: usize,
    read_future: Option<Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send>>>,
    eof: bool,
}

impl REMTransport {
    pub fn new(handle: i32) -> Self {
        debug!("[rem] Creating new REM transport with handle: {}", handle);
        REMTransport {
            handle,
            buffer: Vec::new(),
            buffer_pos: 0,
            read_future: None,
            eof: false,
        }
    }

    pub fn handle(&self) -> i32 {
        self.handle
    }
}

impl AsyncRead for REMTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // 如果缓冲区中有可用数据，直接复制到目标缓冲区
        if self.buffer.len() > self.buffer_pos {
            let available = &self.buffer[self.buffer_pos..];
            let to_copy = std::cmp::min(available.len(), buf.len());
            buf[0..to_copy].copy_from_slice(&available[0..to_copy]);
            self.buffer_pos += to_copy;
            if self.buffer_pos == self.buffer.len() {
                self.buffer.clear();
                self.buffer_pos = 0;
            }
            debug!("[rem] Read {} bytes from buffer for handle {}", to_copy, self.handle);
            return Poll::Ready(Ok(to_copy));
        }

        // 如果已达到 EOF，返回 0
        if self.eof {
            debug!("[rem] EOF reached for handle {}", self.handle);
            return Poll::Ready(Ok(0));
        }

        // 检查是否有正在进行的读取操作
        if let Some(fut) = &mut self.read_future {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(data)) => {
                    self.read_future = None;
                    if data.is_empty() {
                        self.eof = true;
                        debug!("[rem] EOF detected for handle {}", self.handle);
                    } else {
                        self.buffer = data;
                        self.buffer_pos = 0;
                        debug!("[rem] Fetched {} bytes into buffer for handle {}", self.buffer.len(), self.handle);
                    }
                    return self.poll_read(cx, buf);
                }
                Poll::Ready(Err(e)) => {
                    self.read_future = None;
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // 启动新的读取操作
        let handle = self.handle;
        let fut = spawn_blocking(move || {
            let mut read_buf = vec![0; 4096]; // 使用固定大小的缓冲区
            let n = rem::memory_read(handle, &mut read_buf);
            match n {
                Ok(n) => {
                    debug!("[rem] Blocking read fetched {} bytes for handle {}", n, handle);
                    Ok(read_buf[0..n].to_vec())
                }
                Err(e) => {
                    Err(e)
                }
            }
        });

        // 将 JoinHandle 包装为只返回 Result<Vec<u8>, String> 的 Future
        let wrapped_fut = async move {
            match fut.await {
                Ok(result) => result, // 提取内部的 Result<Vec<u8>, String>
                Err(join_err) => {
                    // 将 JoinError 转换为 String 错误
                    Err(format!("Thread pool error: {}", join_err))
                }
            }
        };
        self.read_future = Some(Box::pin(wrapped_fut));
        Poll::Pending
    }
}

impl AsyncWrite for REMTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let handle = self.handle;
        match rem::memory_write(handle, buf) {
            Ok(n) => {
                if n > 0 {
                    debug!("[rem] Wrote {} bytes to handle {}", n, handle);
                }
                Poll::Ready(Ok(n))
            }
            Err(e) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // REM transport doesn't need explicit flushing
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let handle = self.handle;

        match rem::memory_close(handle) {
            Ok(_) => {
                debug!("[rem] Closed handle {}", handle);
                Poll::Ready(Ok(()))
            }
            Err(e) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
            }
        }
    }
}

#[derive(Clone)]
pub struct REMClient {
    pub stream: Stream,
}

impl REMClient {

    pub fn new(cryptor: Cryptor) -> Result<Self> {
        use crate::config::REM;

        let mut cmdline = REM.to_string();
        #[cfg(debug_assertions)]
        cmdline = cmdline + " --debug";
        debug!("[rem] REM cmdline: {}", cmdline);

        match rem::rem_dial(&cmdline) {
            Ok(agent_id) => {
                debug!("[rem] Successfully initialized REM, agent_id: {}", agent_id);
                Ok(REMClient {
                    stream: Stream { cryptor },
                    agent_id,
                })
            }
            Err(e) => {
                Err(anyhow::anyhow!("REM initialization failed: {}", e))
            }
        }
    }
}

#[async_trait]
impl DialerExt for REMClient {
    async fn connect(&mut self, addr: &str) -> Result<REMTransport> {
        // Now dial the specific memory address using agent_id
        debug!("[transport] Dialing memory address: {} ", addr);
        match rem::memory_dial("memory", addr) {
            Ok(handle) => {
                debug!("[transport] Successfully dialed memory, handle: {}", handle);
                Ok(REMTransport::new(handle))
            }
            Err(e) => {
                Err(anyhow::anyhow!("Memory dial failed: {}", e))
            }
        }
    }
}
