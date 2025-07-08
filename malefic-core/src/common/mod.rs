pub mod sys;
pub mod error;

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
use async_std::task::JoinHandle as Handle;
#[cfg(feature = "smol")]
use smol::Task as Handle;
#[cfg(feature = "tokio")]
use tokio::task::JoinHandle as Handle;

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

#[macro_export]
macro_rules! check_body {
    ($field:expr, $variant:path) => {{
        if $field.body.is_none() {
            Err(MaleficError::MissBody)
        } else {
            match $field.body {
                Some($variant(inner_body)) => Ok(inner_body),
                _ => Err(MaleficError::UnExceptBody),
            }
        }
    }};
}