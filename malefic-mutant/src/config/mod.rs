use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use strum_macros::{Display, EnumString};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Implant {
    pub basic: BasicConfig,
    pub implants: ImplantConfig,
    pub pulse: Option<PulseConfig>,
    pub build: Option<BuildConfig>,
    #[serde(default)]
    pub loader: Option<LoaderConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicConfig {
    pub name: String,
    // targets: Vec<String>,
    pub targets: Vec<TargetConfig>,
    // pub protocol: String, // 准备删除
    // pub tls: TLSConfig,
    pub proxy: ProxyConfig,

    // cron表达式配置
    #[serde(default = "default_cron")]
    pub cron: String, // cron表达式，如 "*/5 * * * * * *"

    pub jitter: f64, // 保留jitter
    pub encryption: String,
    pub key: String,
    // pub init_retry: u32,
    pub server_retry: u32,
    pub global_retry: u32,

    // DGA配置
    #[serde(default)]
    pub dga: DgaConfig,
    // Guardrail配置 - 环境检测防护
    #[serde(default)]
    pub guardrail: GuardrailConfig,
    // rem: REMConfig,
    // http: HttpConfig,
    // pub protocol: ()
    pub secure: SecureConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyConfig {
    #[serde(default)]
    pub use_env_proxy: bool,
    #[serde(default)]
    pub url: String,
}

impl std::fmt::Display for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.url.is_empty() && !self.use_env_proxy {
            write!(f, "no proxy")
        } else if self.url.is_empty() && self.use_env_proxy {
            write!(f, "use environment proxy")
        } else {
            write!(f, "{}", self.url)
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            use_env_proxy: false,
            url: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DgaConfig {
    pub enable: bool,
    pub key: String,
    pub interval_hours: u32,
}

impl Default for DgaConfig {
    fn default() -> Self {
        Self {
            enable: false,
            key: "default_dga_key".to_string(),
            interval_hours: 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailConfig {
    pub enable: bool,
    pub require_all: bool,
    pub ip_addresses: Vec<String>,
    pub usernames: Vec<String>,
    pub server_names: Vec<String>,
    pub domains: Vec<String>,
}

impl Default for GuardrailConfig {
    fn default() -> Self {
        Self {
            enable: false,
            require_all: true,
            ip_addresses: vec![],
            usernames: vec![],
            server_names: vec![],
            domains: vec![],
        }
    }
}

fn default_cron() -> String {
    "*/5 * * * * * *".to_string() // 默认每5秒
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    pub address: String,

    // 域名后缀配置（用于DGA等功能）
    // 只有配置了此字段的目标才支持DGA
    #[serde(default)]
    pub domain_suffix: Option<String>,

    tcp: Option<TcpConfig>,
    #[serde(default)]
    pub http: Option<HttpConfig>,
    #[serde(default)]
    pub tls: Option<TLSConfig>,
    #[serde(default)]
    pub rem: Option<REMConfig>,
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TLSConfig {
    pub enable: bool,
    /// TLS版本: "auto", "1.2", "1.3"
    #[serde(default = "default_tls_version")]
    pub version: String,
    /// 服务器名称指示（SNI）
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub skip_verification: bool,
    /// mTLS客户端证书配置
    #[serde(default)]
    pub mtls: Option<MTLSConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MTLSConfig {
    /// 启用mTLS
    pub enable: bool,
    /// 客户端证书文件路径
    pub client_cert: String,
    /// 客户端私钥文件路径
    pub client_key: String,
    /// 用于验证服务端的CA证书路径（可选）
    #[serde(default)]
    pub server_ca: String,
}

// 默认值函数
fn default_tls_version() -> String {
    "auto".to_string()
}
fn default_toolchain() -> String {
    "nightly-2023-09-18".to_string()
}

fn default_obfstr() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildConfig {
    pub zigbuild: bool,
    pub ollvm: Ollvm,
    pub metadata: Option<MetaData>,
    #[serde(default = "default_toolchain")]
    pub toolchain: String,
    #[serde(rename = "remap")]
    pub refresh_remap_path_prefix: bool,
    #[serde(default = "default_obfstr")]
    pub obfstr: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ollvm {
    pub enable: bool,
    pub bcfobf: bool,
    pub splitobf: bool,
    pub subobf: bool,
    pub fco: bool,
    pub constenc: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulseConfig {
    pub flags: Flags,
    pub target: String,
    pub protocol: String,
    pub encryption: String,
    pub key: String,
    pub http: HttpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConfig {
    // TCP特有配置可以在这里添加
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    pub method: String,
    pub path: String,
    // pub host: String,
    pub version: String,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct REMConfig {
    pub link: String,
}

impl TargetConfig {
    /// 获取目标的主机地址（不包含端口）
    pub fn get_host(&self) -> String {
        if let Some(colon_pos) = self.address.rfind(':') {
            self.address[..colon_pos].to_string()
        } else {
            self.address.clone()
        }
    }

    /// 检测目标使用的协议类型
    pub fn detect_protocol(&self) -> String {
        if self.http.is_some() {
            "http".to_string()
        } else if self.rem.is_some() {
            "rem".to_string()
        } else {
            "tcp".to_string() // 默认协议
        }
    }

    /// 检查地址是否为IP地址
    #[allow(dead_code)]
    pub fn is_ip_address(&self) -> bool {
        if let Some(colon_pos) = self.address.rfind(':') {
            let host = &self.address[..colon_pos];
            host.parse::<IpAddr>().is_ok()
        } else {
            self.address.parse::<IpAddr>().is_ok()
        }
    }

    /// 检查地址是否为域名
    #[allow(dead_code)]
    pub fn is_domain_address(&self) -> bool {
        !self.is_ip_address()
    }

    /// 检查是否支持DGA（只有显式配置了domain_suffix才支持）
    pub fn supports_dga(&self) -> bool {
        self.domain_suffix.is_some()
    }

    /// 获取域名后缀
    pub fn get_domain_suffix(&self) -> Option<&String> {
        self.domain_suffix.as_ref()
    }

    /// 获取端口号
    #[allow(dead_code)]
    pub fn get_port(&self) -> String {
        if let Some(colon_pos) = self.address.rfind(':') {
            self.address[colon_pos..].to_string()
        } else {
            ":443".to_string() // 默认端口
        }
    }

    /// 验证域名后缀配置
    pub fn validate_domain_suffix(&self) -> anyhow::Result<()> {
        if let Some(ref suffix) = self.domain_suffix {
            if suffix.is_empty() {
                return Err(anyhow::anyhow!("domain_suffix cannot be empty"));
            }

            // 验证后缀不是IP地址
            if suffix.parse::<std::net::IpAddr>().is_ok() {
                return Err(anyhow::anyhow!(
                    "domain_suffix cannot be an IP address: {}",
                    suffix
                ));
            }

            // 验证后缀是有效的域名格式
            if suffix.contains(':') {
                return Err(anyhow::anyhow!(
                    "domain_suffix should not contain port: {}",
                    suffix
                ));
            }
        }
        Ok(())
    }

    /// 验证目标配置的有效性
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.address.is_empty() {
            return Err(anyhow::anyhow!("Target address cannot be empty"));
        }

        // 验证域名后缀配置
        // self.validate_domain_suffix()?;

        // 验证协议配置互斥性
        let protocol_count = [self.http.is_some(), self.rem.is_some()]
            .iter()
            .filter(|&&x| x)
            .count();

        if protocol_count > 1 {
            return Err(anyhow::anyhow!(
                "Target can only have one protocol configuration"
            ));
        }

        // 验证HTTP配置
        if let Some(http_config) = &self.http {
            if http_config.method.is_empty() || http_config.path.is_empty() {
                return Err(anyhow::anyhow!("HTTP method and path are required"));
            }
        }

        Ok(())
    }
}

impl HttpConfig {
    pub fn build(&self, length: u32) -> String {
        let mut http_request = format!("{} {} HTTP/{}\\r\\n", self.method, self.path, self.version);

        // http_request.push_str(&format!("Host: {}\r\n", host));
        if length > 0 {
            http_request.push_str(&format!("Content-Length: {length}\\r\\n"));
        }
        http_request.push_str("Connection: close\\r\\n");
        for (key, value) in &self.headers {
            http_request.push_str(&format!("{}: {}\\r\\n", key, value));
        }

        http_request.to_string()
    }
}

impl BasicConfig {
    /// 验证所有目标配置
    pub fn validate_targets(&self) -> anyhow::Result<()> {
        if self.targets.is_empty() {
            return Ok(());
        }

        for (index, target) in self.targets.iter().enumerate() {
            target
                .validate()
                .map_err(|e| anyhow::anyhow!("Target {} validation failed: {}", index, e))?;
        }

        // 验证DGA配置
        self.validate_dga_config()?;

        // 验证是否有重复的address
        self.validate_unique_addresses()?;

        Ok(())
    }

    /// 验证地址唯一性
    fn validate_unique_addresses(&self) -> anyhow::Result<()> {
        let mut addresses = std::collections::HashSet::new();
        for target in &self.targets {
            if !addresses.insert(&target.address) {
                return Err(anyhow::anyhow!(
                    "Duplicate address found: {}",
                    target.address
                ));
            }
        }
        Ok(())
    }

    /// 获取所有使用的协议类型
    pub fn get_used_protocols(&self) -> Vec<String> {
        let mut protocols = Vec::new();
        for target in &self.targets {
            let protocol = target.detect_protocol();
            if !protocols.contains(&protocol) {
                protocols.push(protocol);
            }
        }
        protocols
    }

    // 检查是否启用了TLS
    pub fn has_tls_enabled(&self) -> bool {
        self.targets
            .iter()
            .any(|t| t.tls.as_ref().map_or(false, |tls| tls.enable))
    }

    /// 获取支持DGA的targets（只包含配置了dga_suffix的targets）
    pub fn get_dga_targets(&self) -> Vec<&TargetConfig> {
        if self.dga.enable {
            self.targets.iter().filter(|t| t.supports_dga()).collect()
        } else {
            vec![]
        }
    }

    /// 获取所有targets（按配置顺序）
    #[allow(dead_code)]
    pub fn get_all_targets(&self) -> Vec<&TargetConfig> {
        self.targets.iter().collect()
    }

    /// 提取所有域名后缀（只从显式配置的domain_suffix中提取）
    pub fn extract_domain_suffixes(&self) -> Vec<String> {
        if self.dga.enable {
            self.targets
                .iter()
                .filter_map(|t| t.get_domain_suffix().map(|s| s.clone()))
                .collect()
        } else {
            vec![]
        }
    }

    /// 检查是否启用了DGA功能
    #[allow(dead_code)]
    pub fn has_dga_enabled(&self) -> bool {
        self.dga.enable && self.targets.iter().any(|t| t.supports_dga())
    }

    /// 验证DGA配置
    pub fn validate_dga_config(&self) -> anyhow::Result<()> {
        if self.dga.enable {
            if self.dga.key.is_empty() {
                return Err(anyhow::anyhow!(
                    "DGA key cannot be empty when DGA is enabled"
                ));
            }

            if self.dga.interval_hours == 0 || self.dga.interval_hours > 24 {
                return Err(anyhow::anyhow!(
                    "DGA interval_hours must be between 1 and 24"
                ));
            }

            let dga_targets = self.get_dga_targets();
            if dga_targets.is_empty() {
                return Err(anyhow::anyhow!(
                    "DGA is enabled but no targets support DGA. Add domain_suffix to targets that should support DGA."
                ));
            }

            // 验证每个DGA target
            for target in dga_targets {
                target.validate_domain_suffix()?;
            }

            let domain_suffixes = self.extract_domain_suffixes();
            println!(
                "DGA enabled with {} domain suffixes: {:?}",
                domain_suffixes.len(),
                domain_suffixes
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackResource {
    pub src: String,
    pub dst: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplantConfig {
    pub runtime: String,
    pub r#mod: String,
    pub register_info: bool,
    pub hot_load: bool,
    pub modules: Vec<String>,
    pub enable_3rd: bool,
    #[serde(rename = "3rd_modules")]
    pub third_modules: Vec<String>,
    pub flags: Flags,
    pub apis: Apis,
    pub alloctor: Alloctor,
    pub thread_stack_spoofer: bool,
    #[serde(default)]
    pub pack: Option<Vec<PackResource>>,
    pub prelude: String,
    #[serde(default)]
    pub anti: Option<AntiConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flags {
    pub start: u32, // Acutally it's a u8
    pub end: u32,   // Actually it's a u8
    pub magic: String,
    pub artifact_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Apis {
    pub level: String,
    pub priority: ApisPriority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApisPriority {
    pub normal: NormalPriority,
    pub dynamic: DynamicPriority,
    pub syscalls: SyscallPriority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalPriority {
    pub enable: bool,
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicPriority {
    pub enable: bool,
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallPriority {
    pub enable: bool,
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alloctor {
    pub inprocess: String,
    pub crossprocess: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaData {
    pub remap_path: String,
    pub icon: String,
    pub compile_time: String,
    pub file_version: String,
    pub product_version: String,
    pub company_name: String,
    pub product_name: String,
    pub original_filename: String,
    pub file_description: String,
    pub internal_name: String,
    #[serde(default)]
    pub require_admin: bool,
    #[serde(default)]
    pub require_uac: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PESignatureModify {
    pub feature: bool,
    pub modify: PESModify,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PESModify {
    pub magic: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiConfig {
    #[serde(default)]
    pub sandbox: bool,
    #[serde(default)]
    pub vm: bool,
}

#[derive(Debug, Clone, Copy, EnumString, Display, ValueEnum)]
pub enum Version {
    #[strum(serialize = "community")]
    Community,
    #[strum(serialize = "professional")]
    Professional,
    #[strum(serialize = "inner")]
    Inner,
}

#[derive(Debug, Clone, Copy, EnumString, Display)]
pub enum GenerateArch {
    #[strum(serialize = "x64")]
    X64,
    #[strum(serialize = "x86")]
    X86,
}

#[derive(Debug, Clone, Copy, EnumString, Display)]
pub enum TransportProtocolType {
    #[strum(serialize = "tcp")]
    Tcp,
    #[strum(serialize = "http")]
    Http,
    // #[strum(serialize = "https")]
    // Https,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoaderConfig {
    #[serde(default)]
    pub proxydll: Option<ProxyDllConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyDllConfig {
    /// Hijacked function names (comma-separated)
    pub proxyfunc: String,
    /// Raw DLL path (for parsing exports)
    pub raw_dll: String,
    /// Proxied DLL path (runtime forwarding target)
    pub proxied_dll: String,
    /// Proxy DLL name (generated proxy DLL name, optional)
    #[serde(default)]
    pub proxy_dll: Option<String>,
    /// Resource directory for proxy DLL files
    #[serde(default = "default_proxydll_dir")]
    pub resource_dir: String,
    /// Enable block feature
    #[serde(default)]
    pub block: bool,
    /// Enable native_thread feature
    #[serde(default)]
    pub native_thread: bool,
    /// Enable resource packing to program.zip
    #[serde(default)]
    pub pack_resources: bool,
}

fn default_proxydll_dir() -> String {
    "resources/proxydll".to_string()
}
