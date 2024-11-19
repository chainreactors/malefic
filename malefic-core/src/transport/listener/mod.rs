use async_trait::async_trait;
use crate::transport::TransportTrait;

#[cfg(feature = "Transport_Tcp")]
pub mod tcp;

#[cfg(feature = "Transport_Tls")]
pub mod tls;


#[async_trait]
pub trait ListenerExt: Sized {
    async fn bind(addr: &str) -> anyhow::Result<Self>; // 新增 bind 方法
    async fn accept(&mut self) -> anyhow::Result<impl TransportTrait>; // accept 方法用于接收连接
}



cfg_if::cfg_if! {
    if #[cfg(feature = "Transport_Tcp")] {
        pub use tcp::TCPListenerExt as Listener;
    } else {
        compile_error!("No transport selected");
    }
}