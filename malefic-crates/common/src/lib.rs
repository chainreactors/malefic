pub mod errors;
pub mod tinyserde;
pub mod utils;

#[cfg(any(feature = "random_nanorand", feature = "random_getrandom"))]
pub mod random;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod getrandom_compat;

// Runtime mutual exclusion check
#[cfg(any(
    all(feature = "tokio", feature = "async-std"),
    all(feature = "tokio", feature = "smol"),
    all(feature = "async-std", feature = "smol"),
))]
compile_error!("Only one runtime feature (tokio / async-std / smol) can be enabled at a time");

#[cfg(any(feature = "async-std", feature = "smol", feature = "tokio"))]
use std::sync::{Arc, Mutex};

#[cfg(feature = "async-std")]
pub use async_std::task::spawn;
#[cfg(feature = "smol")]
pub use smol::spawn;
#[cfg(feature = "tokio")]
pub use tokio::task::spawn;

#[cfg(feature = "async-std")]
pub use async_std::task::spawn_blocking;
#[cfg(feature = "smol")]
pub use smol::unblock as spawn_blocking;
#[cfg(feature = "tokio")]
pub use tokio::task::spawn_blocking;

#[cfg(feature = "async-std")]
pub use async_std::task::JoinHandle as Handle;
#[cfg(feature = "smol")]
pub use smol::Task as Handle;
#[cfg(feature = "tokio")]
pub use tokio::task::JoinHandle as Handle;

#[async_trait::async_trait]
pub trait CancellableHandle {
    fn cancel(&self);
}

#[cfg(feature = "async-std")]
impl CancellableHandle for Arc<Mutex<Option<Handle<()>>>> {
    fn cancel(&self) {
        if let Ok(mut handle) = self.lock() {
            if let Some(h) = handle.take() {
                h.cancel();
            }
        }
    }
}

#[cfg(feature = "smol")]
impl CancellableHandle for Arc<Mutex<Option<Handle<()>>>> {
    fn cancel(&self) {
        if let Ok(mut handle) = self.lock() {
            if let Some(h) = handle.take() {
                h.cancel();
            }
        }
    }
}

#[cfg(feature = "tokio")]
impl CancellableHandle for Arc<Mutex<Option<Handle<()>>>> {
    fn cancel(&self) {
        if let Ok(mut handle) = self.lock() {
            if let Some(h) = handle.take() {
                h.abort();
            }
        }
    }
}

#[cfg(feature = "async-std")]
pub type RuntimeHandle = Arc<Mutex<Option<Handle<()>>>>;
#[cfg(feature = "smol")]
pub type RuntimeHandle = Arc<Mutex<Option<Handle<()>>>>;
#[cfg(feature = "tokio")]
pub type RuntimeHandle = Arc<Mutex<Option<Handle<()>>>>;

/// Await a spawn handle, returning `Ok(T)` uniformly across runtimes.
///
/// - **tokio**: `JoinHandle<T>.await` returns `Result<T, JoinError>` — maps the error.
/// - **async-std** / **smol**: `.await` returns `T` directly — wraps in `Ok`.
#[cfg(feature = "tokio")]
pub async fn join_handle<T>(handle: Handle<T>) -> anyhow::Result<T>
where
    T: Send + 'static,
{
    handle
        .await
        .map_err(|e| anyhow::anyhow!("task join error: {}", e))
}

#[cfg(feature = "async-std")]
pub async fn join_handle<T>(handle: Handle<T>) -> anyhow::Result<T>
where
    T: Send + 'static,
{
    Ok(handle.await)
}

#[cfg(feature = "smol")]
pub async fn join_handle<T>(handle: Handle<T>) -> anyhow::Result<T>
where
    T: Send + 'static,
{
    Ok(handle.await)
}

/// Runtime-agnostic sleep, backed by `futures_timer::Delay`.
pub async fn sleep(duration: std::time::Duration) {
    futures_timer::Delay::new(duration).await;
}

/// Runtime-agnostic block_on with worker thread hint.
///
/// - **tokio**: builds a multi-thread runtime with `worker_threads` threads
///   and `max_blocking_threads` blocking threads.
/// - **async-std** / **smol**: uses the runtime's native `block_on`;
///   `_worker_threads` / `_max_blocking_threads` are ignored (thread pool is auto-managed).
/// - **no runtime feature**: falls back to `futures::executor::block_on`.
#[cfg(feature = "tokio")]
pub fn block_on<F: std::future::Future>(
    worker_threads: usize,
    max_blocking_threads: usize,
    fut: F,
) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .max_blocking_threads(max_blocking_threads)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(fut)
}

#[cfg(feature = "async-std")]
pub fn block_on<F: std::future::Future>(
    _worker_threads: usize,
    _max_blocking_threads: usize,
    fut: F,
) -> F::Output {
    async_std::task::block_on(fut)
}

#[cfg(feature = "smol")]
pub fn block_on<F: std::future::Future>(
    _worker_threads: usize,
    _max_blocking_threads: usize,
    fut: F,
) -> F::Output {
    smol::block_on(fut)
}

#[cfg(not(any(feature = "tokio", feature = "async-std", feature = "smol")))]
pub fn block_on<F: std::future::Future>(
    _worker_threads: usize,
    _max_blocking_threads: usize,
    fut: F,
) -> F::Output {
    futures::executor::block_on(fut)
}

#[macro_export]
macro_rules! check_body {
    ($field:expr, $variant:path) => {{
        if $field.body.is_none() {
            Err($crate::errors::MaleficError::MissBody)
        } else {
            match $field.body {
                Some($variant(inner_body)) => Ok(inner_body),
                _ => Err($crate::errors::MaleficError::UnExceptBody),
            }
        }
    }};
}
