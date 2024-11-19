#[cfg(feature = "Transport_Tcp")]
pub mod tcp;

#[cfg(feature = "Transport_Tls")]
pub mod tls;

cfg_if::cfg_if! {
    if #[cfg(feature = "Transport_Tcp")] {
        pub use tcp::TCPTransport as Transport;
    } else if #[cfg(feature = "Transport_Tls")]{
        pub use tls::TlsTransport as Transport;
    } else {
        compile_error!("No transport selected");
    }
}