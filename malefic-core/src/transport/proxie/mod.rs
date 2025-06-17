pub mod proxy;

#[cfg(feature = "socks5_proxy")]
pub mod socks5;

#[cfg(feature = "http_proxy")]
pub mod http;

mod error;
mod target;


mod utils;

pub use proxy::{Auth, Proxy, AsyncProxy, HTTPProxy, SOCKS5Proxy};