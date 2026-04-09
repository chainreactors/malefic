use anyhow::Result;
use futures_rustls::TlsConnector;
use malefic_common::debug;
use malefic_config::ServerConfig;
use malefic_gateway::ObfDebug;
use rustls::crypto::ring::cipher_suite;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

#[derive(ObfDebug, Clone)]
pub struct TlsConfig {
    #[obf(skip)]
    pub versions: Vec<&'static rustls::SupportedProtocolVersion>,
    pub server_name: String,
    #[obf(skip)]
    pub cipher_suites: Option<Vec<rustls::SupportedCipherSuite>>,
    pub skip_verification: bool,
    #[obf(skip)]
    pub client_cert_data: Option<(Vec<u8>, Vec<u8>)>,
    #[obf(skip)]
    pub custom_ca: Option<Vec<u8>>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            versions: vec![&TLS13, &TLS12],
            client_cert_data: None,
            server_name: String::new(),
            cipher_suites: None,
            custom_ca: None,
            skip_verification: true,
        }
    }
}

impl TlsConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_versions(
        mut self,
        versions: Vec<&'static rustls::SupportedProtocolVersion>,
    ) -> Self {
        self.versions = versions;
        self
    }

    pub fn tls12_only(mut self) -> Self {
        self.versions = vec![&TLS12];
        self
    }
    pub fn tls13_only(mut self) -> Self {
        self.versions = vec![&TLS13];
        self
    }

    pub fn with_custom_ca(mut self, ca_cert: Vec<u8>) -> Self {
        self.custom_ca = Some(ca_cert);
        self
    }

    pub fn with_client_cert_data(mut self, cert_chain: Vec<u8>, private_key: Vec<u8>) -> Self {
        self.client_cert_data = Some((cert_chain, private_key));
        self
    }

    pub fn with_server_name<S: Into<String>>(mut self, name: S) -> Self {
        self.server_name = name.into();
        self
    }

    pub fn with_cipher_suites(mut self, suites: Vec<rustls::SupportedCipherSuite>) -> Self {
        self.cipher_suites = Some(suites);
        self
    }

    pub fn self_signed(self) -> Self {
        Self {
            versions: vec![&TLS12, &TLS13],
            client_cert_data: None,
            server_name: String::new(),
            cipher_suites: Some(vec![
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                cipher_suite::TLS13_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ]),
            custom_ca: None,
            skip_verification: true,
        }
    }

    pub fn standard() -> Self {
        Self::default()
    }
}

pub struct TlsConnectorBuilder {
    config: TlsConfig,
}

impl TlsConnectorBuilder {
    pub fn new(config: TlsConfig) -> Self {
        Self { config }
    }

    pub fn build(self) -> Result<TlsConnector> {
        debug!(
            "[tls] Building TLS connector with config: {:#?}",
            self.config
        );

        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        if let Some(ca_cert_data) = &self.config.custom_ca {
            let mut reader = ca_cert_data.as_slice();
            for cert in rustls_pemfile::certs(&mut reader) {
                match cert {
                    Ok(c) => {
                        if let Err(_e) = root_store.add(c) {
                            debug!("[tls] Failed to add custom CA: {:?}, but continuing", _e);
                        } else {
                            debug!("[tls] Custom CA added successfully");
                        }
                    }
                    Err(_e) => {
                        debug!("[tls] Failed to parse custom CA cert: {:?}", _e);
                    }
                }
            }
        }

        let versions = self.config.versions.clone();
        let cipher_suites = match &self.config.cipher_suites {
            Some(suites) => suites.clone(),
            None => {
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
            }
        };

        let provider = rustls::crypto::CryptoProvider {
            cipher_suites,
            kx_groups: rustls::crypto::ring::default_provider().kx_groups,
            ..rustls::crypto::ring::default_provider()
        };

        let builder = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&versions)?;

        let client_config = if self.config.skip_verification {
            let builder = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification));
            match &self.config.client_cert_data {
                Some((cert_chain_data, private_key_data)) => {
                    debug!("[tls] Setting up client certificate for mTLS");
                    let (certs, key) = parse_client_cert(cert_chain_data, private_key_data)?;
                    builder
                        .with_client_cert_resolver(Arc::new(StaticCertResolver::new(certs, key)?))
                }
                None => builder.with_no_client_auth(),
            }
        } else {
            let builder = builder.with_root_certificates(root_store);
            match &self.config.client_cert_data {
                Some((cert_chain_data, private_key_data)) => {
                    debug!("[tls] Setting up client certificate for mTLS");
                    let (certs, key) = parse_client_cert(cert_chain_data, private_key_data)?;
                    builder
                        .with_client_cert_resolver(Arc::new(StaticCertResolver::new(certs, key)?))
                }
                None => builder.with_no_client_auth(),
            }
        };

        Ok(TlsConnector::from(Arc::new(client_config)))
    }
}

fn parse_client_cert(
    cert_chain_data: &[u8],
    private_key_data: &[u8],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &*cert_chain_data)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let key = rustls_pemfile::private_key(&mut &*private_key_data)?
        .ok_or_else(|| anyhow::anyhow!("No valid private key found"))?;

    Ok((certs, key))
}

/// A simple resolver that always returns the same client cert + key.
#[derive(Debug)]
struct StaticCertResolver {
    certified_key: Arc<rustls::sign::CertifiedKey>,
}

impl StaticCertResolver {
    fn new(certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result<Self> {
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|e| anyhow::anyhow!("Unsupported private key type: {}", e))?;
        Ok(Self {
            certified_key: Arc::new(rustls::sign::CertifiedKey::new(certs, signing_key)),
        })
    }
}

impl rustls::client::ResolvesClientCert for StaticCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.certified_key.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

pub fn build_tls_config(config: ServerConfig) -> TlsConfig {
    debug!("address: {}", config.address);
    let tls_config = config.tls_config.as_ref().unwrap();

    let mut config = match tls_config.version.as_str() {
        "1.2" => TlsConfig::new().tls12_only(),
        "1.3" => TlsConfig::new().tls13_only(),
        _ => TlsConfig::new(),
    };

    config = config.with_server_name(tls_config.sni.clone());

    // Implant uses skip_verification = true by default (self-signed certs).
    // Encryption is always active; certificate chain verification is optional.
    config.skip_verification = true;

    // Load server CA if provided (enables optional certificate verification
    // when skip_verification is explicitly set to false in config)
    if !tls_config.server_ca.is_empty() {
        config = config.with_custom_ca(tls_config.server_ca.clone());
        config.skip_verification = tls_config.skip_verification;
    } else if let Some(ref mtls) = tls_config.mtls_config {
        if mtls.enable && !mtls.server_ca.is_empty() {
            config = config.with_custom_ca(mtls.server_ca.clone());
            config.skip_verification = tls_config.skip_verification;
        }
    }

    // Load mTLS client certificate (for encrypted channel authentication)
    if let Some(mtls_config) = &tls_config.mtls_config {
        if mtls_config.enable
            && !mtls_config.client_cert.is_empty()
            && !mtls_config.client_key.is_empty()
        {
            debug!("[tls] Loading mTLS client certificate");
            config = config.with_client_cert_data(
                mtls_config.client_cert.clone(),
                mtls_config.client_key.clone(),
            );
        }
    }

    config
}
