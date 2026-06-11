use crate::config::{GenerateArch, PulseConfig, TransportApiType, TransportProtocolType, Version};

mod http;
mod tcp;
pub(crate) mod utils;
mod winhttp;
mod wininet;

pub fn pulse_generate(
    config: PulseConfig,
    arch: GenerateArch,
    version: Version,
    source: bool,
) -> anyhow::Result<()> {
    let protocol: TransportProtocolType = config.protocol.parse()?;
    let api_type: TransportApiType = if config.api_type.is_empty() {
        TransportApiType::Raw
    } else {
        config.api_type.parse()?
    };

    let tls = matches!(protocol, TransportProtocolType::Https);

    match (protocol, api_type) {
        (TransportProtocolType::Tcp, _) => tcp::generate_tcp_pulse(config, arch, &version, source),
        (TransportProtocolType::Http | TransportProtocolType::Https, TransportApiType::Raw) => {
            if tls {
                anyhow::bail!("https protocol requires api_type 'winhttp' or 'wininet', raw socket does not support TLS");
            }
            http::generate_http_pulse(config, arch, &version, source)
        }
        (TransportProtocolType::Http | TransportProtocolType::Https, TransportApiType::WinHttp) => {
            winhttp::generate_winhttp_pulse(config, arch, &version, source, tls)
        }
        (TransportProtocolType::Http | TransportProtocolType::Https, TransportApiType::WinInet) => {
            wininet::generate_wininet_pulse(config, arch, &version, source, tls)
        }
    }
}

#[allow(dead_code)]
pub fn djb2_hash(s: &str) -> u32 {
    utils::djb2_hash(s)
}
