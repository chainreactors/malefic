mod config;
mod runtime;
use std::time::Duration;

pub use config::{
    ServerConfig,
    ProtocolType,
    SessionConfig,
    TransportConfig,
    // TCP
    TcpConfig,
    SocketOptions,
    // HTTP
    HttpRequestConfig,
    // REM
    RemConfig,
    // TLS
    MTLSConfig,
    TlsConfig,
    ProxyConfig,
    // Guardrail
    GuardrailConfig,
};
pub use runtime::{
    BlobError,
    ConfigBlobText,
    RuntimeConfig,
    CONFIG_BLOB_B64_LEN,
    CONFIG_BLOB_TEXT,
    CONFIG_BLOB_TEXT_LEN,
    decode_runtime_config_bytes,
    decode_runtime_config_str,
    get_transport_key,
    load_runtime_config,
    update_runtime_key,
};
#[cfg(feature = "encoder")]
pub use runtime::encode_runtime_config;
use malefic_gateway::lazy_static;

lazy_static! {
    pub static ref RUNTIME_CONFIG: RuntimeConfig = load_runtime_config(RuntimeConfig {
        cron: "*/5 * * * * * *".to_string(),
        jitter: 0.2f64,
        keepalive: false,
        retry: 10u32,
        max_cycles: -1i32,
        name: "malefic".to_string(),
        key: "maliceofinternal".to_string().into_bytes(),
        use_env_proxy: false,
        proxy_url: "".to_string(),
        proxy_scheme: "".to_string(),
        proxy_host: "".to_string(),
        proxy_port: "".to_string(),
        proxy_username: "".to_string(),
        proxy_password: "".to_string(),
        dga_enable: false,
        dga_key: String::new(),
        dga_interval_hours: 8u32,
        guardrail: GuardrailConfig {
            ip_addresses: Vec::new(),
            usernames: Vec::new(),
            server_names: Vec::new(),
            domains: Vec::new(),
            require_all: true,
        },
        server_configs: {
            let mut configs = Vec::new();
            {
                let transport_config = TransportConfig::Tcp(TcpConfig {});
                let mut session_config = SessionConfig::default_for_transport(&transport_config, false);
                configs.push(
                    ServerConfig {
                        address: "127.0.0.1:5001".to_string(),
                        protocol: ProtocolType::Tcp,
                        session_config,
                        transport_config,
                tls_config: None,
                proxy_config: None,
                domain_suffix: None,
                    }
                );
            }

            configs
        },
        max_packet_length: 0usize,
    });
    // Basic configuration
    pub static ref CRON: String = RUNTIME_CONFIG.cron.clone();
    pub static ref JITTER: f64 = RUNTIME_CONFIG.jitter;
    pub static ref KEEPALIVE: bool = RUNTIME_CONFIG.keepalive;
    // Target server fault tolerance configuration
    pub static ref RETRY: u32 = RUNTIME_CONFIG.retry;
    pub static ref MAX_CYCLES: i32 = RUNTIME_CONFIG.max_cycles;
    // Encryption configuration
    pub static ref NAME: String = RUNTIME_CONFIG.name.clone();
    pub static ref KEY: Vec<u8> = RUNTIME_CONFIG.key.clone();
    // Proxy configuration
    pub static ref USE_ENV_PROXY: bool = RUNTIME_CONFIG.use_env_proxy;
    pub static ref PROXY_URL: String = RUNTIME_CONFIG.proxy_url.clone();
    pub static ref PROXY_SCHEME: String = RUNTIME_CONFIG.proxy_scheme.clone();
    pub static ref PROXY_HOST: String = RUNTIME_CONFIG.proxy_host.clone();
    pub static ref PROXY_PORT: String = RUNTIME_CONFIG.proxy_port.clone();
    pub static ref PROXY_USERNAME: String = RUNTIME_CONFIG.proxy_username.clone();
    pub static ref PROXY_PASSWORD: String = RUNTIME_CONFIG.proxy_password.clone();
    // DGA configuration
    pub static ref DGA_ENABLE: bool = RUNTIME_CONFIG.dga_enable;
    pub static ref DGA_KEY: String = RUNTIME_CONFIG.dga_key.clone();
    pub static ref DGA_INTERVAL_HOURS: u32 = RUNTIME_CONFIG.dga_interval_hours;
    // Guardrail configuration
    pub static ref GUARDRAIL_CONFIG: GuardrailConfig = RUNTIME_CONFIG.guardrail.clone();
    // Multi-server configuration - use Vec to maintain configuration order
    pub static ref SERVER_CONFIGS: Vec<ServerConfig> = RUNTIME_CONFIG.server_configs.clone();
    // Packet chunking configuration
    pub static ref MAX_PACKET_LENGTH: usize = RUNTIME_CONFIG.max_packet_length;
}

#[cfg(feature = "secure")]
lazy_static! {
    pub static ref AGE_PRIVATE_KEY: String = String::new();
    pub static ref AGE_PUBLIC_KEY: String = String::new();
}
