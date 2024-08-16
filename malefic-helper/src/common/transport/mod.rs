/*
    Refactor is on the way :)
*/

#[cfg(feature = "Common_Transport_Dns")]
pub mod Dns;
#[cfg(feature = "Common_Transport_Http")]
pub mod Http;
#[cfg(feature = "Common_Transport_Tls")]
pub mod tls;
#[cfg(feature = "Common_Transport_Wireguard")]
pub mod Wireguard;
#[cfg(feature = "Common_Transport_Tcp")]
pub mod tcp;

cfg_if::cfg_if! {
    if #[cfg(feature = "Common_Transport_Tcp")] {
        pub use tcp::TcpClient as Client;
    } else if #[cfg(feature = "Common_Transport_Dns")] {
        pub use Dns::DnsClient as Client;
    } else if #[cfg(feature = "Common_Transport_Http")] {
        pub use Http::HttpClient as Client;
    } else if #[cfg(feature = "Common_Transport_Tls")] {
        pub use tls::TlsClient as Client;
    } else if #[cfg(feature = "Common_Transport_Wireguard")] {
        pub use Wireguard::WireguardClient as Client;
    } else {
        compile_error!("No transport selected");
    }
}

use async_trait::async_trait;

#[async_trait]
pub trait ClientTrait {
    type Config;
    fn new(config: Self::Config) -> Option<Self> where Self: Sized;
    fn set_ca(&mut self, ca: Vec<u8>);
    async fn recv(&self) -> Vec<u8>;
    async fn send(&self, data: Vec<u8>) -> usize;
    async fn send_with_read(&self, data: Vec<u8>) -> Vec<u8>;
}


