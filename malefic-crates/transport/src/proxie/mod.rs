pub mod proxy;

#[cfg(feature = "proxy")]
pub mod socks5;

#[cfg(feature = "proxy")]
pub mod http;

mod error;
mod target;
mod utils;

pub use proxy::{AsyncProxy, Auth, HTTPProxy, Proxy, SOCKS5Proxy};
