/// CarbonCopy: clone a TLS certificate from a remote host and inject it into a PE file.
///
/// Connects to a remote server via TLS, extracts the server certificate chain,
/// and constructs a WIN_CERTIFICATE structure to embed in the target PE.
use anyhow::{anyhow, Result};
use std::io::Read;
use std::net::TcpStream;
use std::sync::Arc;

use super::inject::SignatureInjector;

/// Connect to a remote host via TLS and extract the server certificate chain as DER bytes.
fn fetch_remote_certificates(host: &str, port: u16) -> Result<Vec<Vec<u8>>> {
    // Use a permissive verifier to accept any cert (including self-signed)
    let config = build_permissive_config();

    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| anyhow!("Invalid server name '{}': {}", host, e))?;

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| anyhow!("TLS connection setup failed: {}", e))?;

    let mut sock = TcpStream::connect(format!("{}:{}", host, port))
        .map_err(|e| anyhow!("TCP connection to {}:{} failed: {}", host, port, e))?;

    // Complete the TLS handshake
    let mut stream = rustls::Stream::new(&mut conn, &mut sock);
    // Read a single byte to trigger handshake completion (ignore errors — we just need the handshake)
    let mut buf = [0u8; 1];
    let _ = stream.read(&mut buf);

    let certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow!("No certificates received from {}:{}", host, port))?;

    if certs.is_empty() {
        return Err(anyhow!("Empty certificate chain from {}:{}", host, port));
    }

    Ok(certs.iter().map(|c| c.as_ref().to_vec()).collect())
}

/// Build a rustls ClientConfig that does not verify server certificates.
/// This allows us to extract certificates from any server, even self-signed.
fn build_permissive_config() -> rustls::ClientConfig {
    let verifier = Arc::new(NoVerifier);
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

/// A certificate verifier that accepts everything.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
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

/// Construct a WIN_CERTIFICATE structure from DER certificate data.
///
/// WIN_CERTIFICATE layout:
///   dwLength:          u32 (total size including header)
///   wRevision:         u16 (0x0200 = WIN_CERT_REVISION_2_0)
///   wCertificateType:  u16 (0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA)
///   bCertificate:      [u8] (DER-encoded certificate data)
///
/// The structure is padded to 8-byte alignment.
fn build_win_certificate(der_certs: &[Vec<u8>]) -> Vec<u8> {
    // Concatenate all cert DER data
    let total_cert_len: usize = der_certs.iter().map(|c| c.len()).sum();
    let header_len = 8u32; // dwLength(4) + wRevision(2) + wCertificateType(2)
    let dw_length = header_len + total_cert_len as u32;

    // Align to 8 bytes
    let aligned_length = (dw_length + 7) & !7;

    let mut result = Vec::with_capacity(aligned_length as usize);
    result.extend_from_slice(&dw_length.to_le_bytes()); // dwLength
    result.extend_from_slice(&0x0200u16.to_le_bytes()); // wRevision = WIN_CERT_REVISION_2_0
    result.extend_from_slice(&0x0002u16.to_le_bytes()); // wCertificateType = PKCS_SIGNED_DATA

    for cert in der_certs {
        result.extend_from_slice(cert);
    }

    // Pad to 8-byte alignment
    while result.len() < aligned_length as usize {
        result.push(0);
    }

    result
}

/// Load certificate from a local DER or PEM file.
fn load_cert_from_file(cert_path: &str) -> Result<Vec<Vec<u8>>> {
    let data = std::fs::read(cert_path)
        .map_err(|e| anyhow!("Failed to read certificate file '{}': {}", cert_path, e))?;

    // Check if PEM (starts with "-----BEGIN")
    if data.starts_with(b"-----BEGIN") {
        let pem_str = String::from_utf8(data)
            .map_err(|_| anyhow!("Certificate file contains invalid UTF-8"))?;

        let mut certs = Vec::new();
        let mut in_cert = false;
        let mut b64_buf = String::new();

        for line in pem_str.lines() {
            if line.starts_with("-----BEGIN") {
                in_cert = true;
                b64_buf.clear();
            } else if line.starts_with("-----END") {
                in_cert = false;
                let der =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64_buf)
                        .map_err(|e| anyhow!("Failed to decode PEM base64: {}", e))?;
                certs.push(der);
            } else if in_cert {
                b64_buf.push_str(line.trim());
            }
        }

        if certs.is_empty() {
            return Err(anyhow!("No certificates found in PEM file"));
        }
        Ok(certs)
    } else {
        // Assume DER format
        Ok(vec![data])
    }
}

/// CarbonCopy: clone a certificate and inject it into a target PE.
///
/// - If `host` is provided, fetches the certificate from the remote server via TLS.
/// - If `cert_file` is provided, loads the certificate from a local DER/PEM file.
/// - Constructs a WIN_CERTIFICATE and injects it into the target PE.
pub fn carbon_copy(
    host: Option<&str>,
    port: u16,
    cert_file: Option<&str>,
    target_path: &str,
    output_path: Option<&str>,
) -> Result<String> {
    let der_certs = if let Some(cert_path) = cert_file {
        load_cert_from_file(cert_path)?
    } else if let Some(hostname) = host {
        fetch_remote_certificates(hostname, port)?
    } else {
        return Err(anyhow!("Either --host or --cert-file must be specified"));
    };

    let win_cert = build_win_certificate(&der_certs);

    let result_path =
        SignatureInjector::inject_signature_data(&win_cert, target_path, output_path)?;

    Ok(result_path)
}
