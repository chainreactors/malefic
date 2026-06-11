use crate::DialerExt;
use anyhow::Result;
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::{AsyncRead, AsyncWrite, FutureExt, Stream};
use futures_timer::Delay;
use malefic_common::debug;
use malefic_common::spawn_blocking;
use malefic_config::{RemConfig, ServerConfig, TransportConfig, SERVER_CONFIGS};
use malefic_rem as rem;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

/// Guard that closes the REM handle if a `spawn_blocking(MemoryWrite)`
/// is still running when the future is dropped (e.g., due to session-layer
/// write timeout).  Closing the handle interrupts the blocked FFI call,
/// freeing the thread back to the pool.
struct WriteGuard {
    handle: i32,
    /// Set to `true` by the `spawn_blocking` closure after `memory_write` returns.
    completed: Arc<AtomicBool>,
    /// Shared with `REMTransport.closed` — ensures only one close happens.
    transport_closed: Arc<AtomicBool>,
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        if !self.completed.load(Ordering::Acquire)
            && !self.transport_closed.swap(true, Ordering::AcqRel)
        {
            let handle = self.handle;
            debug!(
                "[rem] WriteGuard: closing handle {} to free blocked write thread",
                handle
            );
            std::thread::spawn(move || {
                let _ = rem::memory_close(handle);
            });
        }
    }
}

/// Async bridge for the blocking CGo REM transport.
///
/// Architecture — **no FFI call ever touches the async executor**:
///
///   - `poll_read`: drains a `futures::channel::mpsc` fed by a dedicated
///     read thread. The thread calls `memory_try_read(handle, buf)` in a
///     loop and forwards ready chunks through the channel.
///   - `poll_write`: `spawn_blocking(MemoryWrite)` with a `WriteGuard`
///     that closes the handle if the future is dropped before completion.
///   - `poll_close`: `spawn_blocking(MemoryClose)`.
///   - `Drop`: `std::thread::spawn(memory_close)` — never blocks executor.
///
/// One dedicated thread per transport is created for reads.
pub struct REMTransport {
    handle: i32,
    /// Internal buffer for partial consumption of a read chunk.
    buffer: Vec<u8>,
    buffer_pos: usize,
    /// Receives read data from the dedicated read thread.
    read_rx: mpsc::Receiver<Result<Vec<u8>, String>>,
    /// Pending `spawn_blocking(MemoryWrite)` future with close guard.
    write_future: Option<Pin<Box<dyn Future<Output = Result<usize, String>> + Send>>>,
    /// Pending `spawn_blocking(MemoryClose)` future.
    close_future: Option<Pin<Box<dyn Future<Output = Result<(), String>> + Send>>>,
    /// Shared close flag — prevents double-close between Drop and WriteGuard.
    closed: Arc<AtomicBool>,
}

impl REMTransport {
    pub fn new(handle: i32, _config: &RemConfig) -> Self {
        debug!("[rem] Creating new REM transport with handle: {}", handle);

        let closed = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel(1); // Single-slot for backpressure
        let read_buffer_size = 64 * 1024; // 64KB buffer for fewer reads
        let read_poll_interval = Duration::from_millis(1);

        // Spawn dedicated read thread — all read FFI happens here, never on executor.
        let closed_clone = closed.clone();
        std::thread::spawn(move || {
            Self::read_thread(
                handle,
                tx,
                closed_clone,
                read_buffer_size,
                read_poll_interval,
            );
        });

        REMTransport {
            handle,
            buffer: Vec::new(),
            buffer_pos: 0,
            read_rx: rx,
            write_future: None,
            close_future: None,
            closed,
        }
    }

    /// Dedicated read thread.  Calls `memory_try_read` (non-blocking) in a
    /// loop.  When no data is available, sleeps for `READ_THREAD_POLL_INTERVAL`
    /// and retries.  No timeout parameter is passed to the FFI — the only
    /// timeout lives in the Rust session layer (`read_exact_with_idle_timeout`).
    ///
    /// Exit conditions:
    ///   - `closed` flag is set (by `poll_close` / `Drop`)
    ///   - FFI returns a real error (e.g., `MemoryClose` interrupted the conn)
    ///   - Channel receiver is dropped (transport dropped)
    fn read_thread(
        handle: i32,
        mut tx: mpsc::Sender<Result<Vec<u8>, String>>,
        closed: Arc<AtomicBool>,
        read_buffer_size: usize,
        read_poll_interval: Duration,
    ) {
        let mut buf = vec![0u8; read_buffer_size.max(1)];
        loop {
            if closed.load(Ordering::Acquire) {
                break;
            }

            match rem::memory_try_read(handle, &mut buf) {
                Ok(0) => {
                    // EOF from underlying conn.
                    debug!("[rem] Read thread EOF for handle {}", handle);
                    break;
                }
                Ok(n) => {
                    debug!("[rem] Read thread got {} bytes for handle {}", n, handle);
                    let data = buf[..n].to_vec();
                    // Send with backpressure: retry until channel has space or closed.
                    let mut retry_count = 0;
                    loop {
                        if closed.load(Ordering::Acquire) {
                            return;
                        }
                        match tx.try_send(Ok(data.clone())) {
                            Ok(()) => {
                                if retry_count > 0 {
                                    debug!(
                                        "[rem] Channel send succeeded after {} retries",
                                        retry_count
                                    );
                                }
                                break;
                            }
                            Err(e) if e.is_full() => {
                                if retry_count == 0 {
                                    debug!("[rem] Channel full, entering retry loop");
                                }
                                retry_count += 1;
                                std::thread::sleep(read_poll_interval);
                            }
                            Err(_) => return, // disconnected
                        }
                    }
                }
                Err(rem::RemError::WouldBlock) => {
                    // No data available right now.  Sleep briefly, then retry.
                    std::thread::sleep(read_poll_interval);
                    continue;
                }
                Err(rem::RemError::Other(e)) => {
                    debug!("[rem] Read thread error for handle {}: {}", handle, e);
                    let _ = tx.try_send(Err(e));
                    break;
                }
            }
        }
        debug!("[rem] Read thread exiting for handle {}", handle);
    }

    pub fn handle(&self) -> i32 {
        self.handle
    }

    /// Poll the pending write future, if any.
    fn poll_pending_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        if let Some(fut) = &mut self.write_future {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(n)) => {
                    self.write_future = None;
                    Poll::Ready(Ok(n))
                }
                Poll::Ready(Err(e)) => {
                    self.write_future = None;
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(0))
        }
    }

    /// Initiate close if not already started.
    fn poll_close_impl(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(fut) = &mut self.close_future {
            return match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {
                    self.close_future = None;
                    self.closed.store(true, Ordering::Release);
                    debug!("[rem] Closed handle {}", self.handle);
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => {
                    self.close_future = None;
                    self.closed.store(true, Ordering::Release);
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
                }
                Poll::Pending => Poll::Pending,
            };
        }

        if self.closed.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }

        // Mark closed before spawning — prevents WriteGuard from racing
        // and signals the read thread to exit.
        self.closed.store(true, Ordering::Release);

        let handle = self.handle;
        let fut = spawn_blocking(move || rem::memory_close(handle));
        let wrapped = async move {
            #[cfg(feature = "tokio")]
            {
                // tokio: outer Result from JoinHandle
                match fut.await {
                    Ok(result) => result,
                    Err(join_err) => Err(format!("Thread pool error: {}", join_err)),
                }
            }
            #[cfg(not(feature = "tokio"))]
            {
                // async-std/smol: no outer Result, return directly
                fut.await
            }
        };
        self.close_future = Some(Box::pin(wrapped));
        self.poll_close_impl(cx)
    }
}

impl AsyncRead for REMTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // 1. Drain internal buffer first.
        if self.buffer.len() > self.buffer_pos {
            let available = &self.buffer[self.buffer_pos..];
            let to_copy = available.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&available[..to_copy]);
            self.buffer_pos += to_copy;
            if self.buffer_pos == self.buffer.len() {
                self.buffer.clear();
                self.buffer_pos = 0;
            }
            return Poll::Ready(Ok(to_copy));
        }

        // 2. Poll channel for data from the dedicated read thread.
        //    No FFI call happens here — the executor is never blocked.
        match Pin::new(&mut self.read_rx).poll_next(cx) {
            Poll::Ready(Some(Ok(data))) => {
                debug!("[rem] poll_read received {} bytes from channel", data.len());
                let to_copy = data.len().min(buf.len());
                buf[..to_copy].copy_from_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.buffer = data;
                    self.buffer_pos = to_copy;
                }
                Poll::Ready(Ok(to_copy))
            }
            Poll::Ready(Some(Err(e))) => {
                debug!(
                    "[rem] Read error from channel for handle {}: {}",
                    self.handle, e
                );
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
            }
            Poll::Ready(None) => {
                // Channel closed — read thread exited.
                debug!("[rem] Channel closed for handle {}", self.handle);
                Poll::Ready(Ok(0))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for REMTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let had_pending = self.write_future.is_some();
        match self.as_mut().poll_pending_write(cx) {
            Poll::Ready(Ok(n)) if had_pending => return Poll::Ready(Ok(n)),
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let handle = self.handle;
        let data = buf.to_vec();
        let completed = Arc::new(AtomicBool::new(false));
        let completed_inner = completed.clone();

        let fut = spawn_blocking(move || {
            let result = rem::memory_write(handle, &data);
            completed_inner.store(true, Ordering::Release);
            result
        });

        let guard = WriteGuard {
            handle,
            completed,
            transport_closed: self.closed.clone(),
        };
        let wrapped = async move {
            let _guard = guard; // dropped when future completes or is abandoned
            #[cfg(feature = "tokio")]
            {
                // tokio: outer Result from JoinHandle
                fut.await.map_err(|e| format!("Thread pool error: {}", e))?
            }
            #[cfg(not(feature = "tokio"))]
            {
                // async-std/smol: no outer Result, return directly
                fut.await
            }
        };
        self.write_future = Some(Box::pin(wrapped));
        self.poll_pending_write(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_pending_write(cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_pending_write(cx) {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        self.poll_close_impl(cx)
    }
}

impl Drop for REMTransport {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let handle = self.handle;
            debug!("[rem] Drop: closing handle {} asynchronously", handle);
            // Never block the executor — close on a dedicated thread.
            // This also interrupts the read thread's blocked FFI call and
            // any pending spawn_blocking(MemoryWrite) on the same handle.
            std::thread::spawn(move || {
                let _ = rem::memory_close(handle);
            });
        }
    }
}

fn connect_timeout_for_config(config: &ServerConfig) -> Duration {
    config.session_config.connect_timeout
}

// ========================================================================
// REMClient
// ========================================================================

#[derive(Clone)]
pub struct REMClient {
    pub agent_id: String,
    cmdline: String,
    stale: bool,
}

impl REMClient {
    pub fn new() -> Result<Self> {
        Self::new_with_alias(None)
    }

    pub fn new_with_alias(alias: Option<&str>) -> Result<Self> {
        let first_rem_config = SERVER_CONFIGS
            .iter()
            .find_map(|config| {
                if let TransportConfig::Rem(rem_config) = &config.transport_config {
                    Some(rem_config)
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow::anyhow!("No REM configuration found"))?;

        let mut cmdline = first_rem_config.link.clone();
        if let Some(a) = alias {
            cmdline = format!("{} -a {}", cmdline, a);
        }
        if cfg!(debug_assertions) {
            cmdline = cmdline + " --debug";
        }
        debug!("[rem] REM cmdline: {}", cmdline);

        match rem::rem_dial(&cmdline) {
            Ok(agent_id) => {
                debug!("[rem] Successfully initialized REM, agent_id: {}", agent_id);
                Ok(REMClient {
                    agent_id,
                    cmdline,
                    stale: false,
                })
            }
            Err(e) => Err(anyhow::anyhow!("REM initialization failed: {}", e)),
        }
    }

    fn reinitialize(&mut self) -> Result<()> {
        debug!("[rem] Cleaning up dead agent...");
        rem::cleanup();

        debug!("[rem] Reinitializing REM with cmdline: {}", self.cmdline);
        match rem::rem_dial(&self.cmdline) {
            Ok(agent_id) => {
                debug!("[rem] REM reinitialized, new agent_id: {}", agent_id);
                self.agent_id = agent_id;
                self.stale = false;
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!("REM reinitialization failed: {}", e)),
        }
    }

    fn dial_with_retry(&mut self, config: &ServerConfig) -> Result<REMTransport> {
        let address = config.address.as_str();
        let rem_config = match &config.transport_config {
            TransportConfig::Rem(rem_config) => rem_config,
            _ => return Err(anyhow::anyhow!("REM dial requested for non-REM target")),
        };
        if !self.stale {
            debug!("[rem] Dialing memory address: {:?}", address);
            match rem::memory_dial("memory", address) {
                Ok(handle) => {
                    debug!("[rem] Dialed memory, handle: {}", handle);
                    return Ok(REMTransport::new(handle, rem_config));
                }
                Err(e) => {
                    debug!("[rem] Memory dial failed: {}, will reinitialize...", e);
                }
            }
        }

        match self.reinitialize() {
            Ok(()) => {}
            Err(e) => {
                self.stale = true;
                return Err(e);
            }
        }

        debug!("[rem] Retrying memory dial after reinit: {:?}", address);
        match rem::memory_dial("memory", address) {
            Ok(handle) => {
                debug!("[rem] Dialed memory after reinit, handle: {}", handle);
                Ok(REMTransport::new(handle, rem_config))
            }
            Err(e) => {
                self.stale = true;
                Err(anyhow::anyhow!("Memory dial failed after reinit: {}", e))
            }
        }
    }
}

#[async_trait]
impl DialerExt for REMClient {
    async fn connect(&mut self, target: &crate::server_manager::Target) -> Result<REMTransport> {
        let config = target.server_config().clone();
        let connect_timeout = connect_timeout_for_config(&config);
        let mut client = self.clone();

        let dial_future = spawn_blocking(move || {
            let transport = client.dial_with_retry(&config)?;
            Ok::<(REMTransport, REMClient), anyhow::Error>((transport, client))
        })
        .fuse();

        let timeout = Delay::new(connect_timeout).fuse();
        futures::pin_mut!(dial_future, timeout);

        let result: Result<(REMTransport, REMClient), anyhow::Error> = futures::select! {
            r = dial_future => {
                #[cfg(feature = "tokio")]
                {
                    // tokio: outer Result from JoinHandle, inner Result from dial
                    r.map_err(|e| anyhow::anyhow!("spawn_blocking join error: {}", e))?
                }
                #[cfg(not(feature = "tokio"))]
                {
                    // async-std/smol: r is already the inner Result (Result<(..., ...), _>)
                    r
                }
            },
            _ = timeout => Err(anyhow::anyhow!(
                "connect timed out after {:?}", connect_timeout
            )),
        };

        let (transport, updated_client) = result?;
        self.agent_id = updated_client.agent_id;
        self.stale = updated_client.stale;
        Ok(transport)
    }
}
