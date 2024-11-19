use async_trait::async_trait;
use crate::transport::TransportTrait;

#[cfg(feature = "Transport_Tcp")]
pub mod tcp;

#[cfg(feature = "Transport_Tls")]
pub mod tls;



#[async_trait]
pub trait DialerExt {
    async fn connect(&mut self, addr: &str) -> anyhow::Result<impl TransportTrait>;
}


