//! Certificate pinning security module

#[cfg(feature = "cert-pinning")]
use crate::error::KoavaError;
use crate::error::Result;

#[cfg(feature = "cert-pinning")]
use std::sync::Arc;

#[cfg(feature = "cert-pinning")]
use base64::Engine;
#[cfg(feature = "cert-pinning")]
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
#[cfg(feature = "cert-pinning")]
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
#[cfg(feature = "cert-pinning")]
use rustls::{DigitallySignedStruct, SignatureScheme};

/// Default server public key for certificate pinning
pub const DEFAULT_SERVER_PUBLIC_KEY: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArpsodREeskPDtrofwlZFfcB1vkvUZzXkdjBS7hF5Zu4T8YjLRYqLWpdUU3bCalPt+H6ghBNlTSXRqU2RD1YkDRamnub6X8nWZYIkLNzHqb0scexzO6k3yhlkLfCgVQScGyBmcZKSx1WygaakX11iUs1hTv/onsLah50n6rrOeDmnNTk3yeHrF1H/DfizVwi/FLMPw2ypxvJMxRrUBPIpX84kWuJaEQrGMuvkPioLCobkqQnd17PbUtVrkGHMXUorEUdDGV6O9xJ5+OdkesjQjhYmysZ62Sv4WCAcIwAbCZoO01v1q2DwqOZQiGtwbUHNcPAsZ/PlRzax3s9RRmc0+QIDAQAB";

/// Verify server certificate against pinned public key
pub async fn verify_certificate_pinning(endpoint: &str, server_public_key: &str) -> Result<()> {
    #[cfg(not(feature = "cert-pinning"))]
    {
        let _ = endpoint;
        let _ = server_public_key;
        Ok(())
    }

    #[cfg(feature = "cert-pinning")]
    {
        verify_certificate_pinning_impl(endpoint, server_public_key).await
    }
}

#[cfg(feature = "cert-pinning")]
async fn verify_certificate_pinning_impl(endpoint: &str, server_public_key: &str) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let parsed_url = url::Url::parse(endpoint)
        .map_err(|_| KoavaError::invalid_input("Invalid server URL format"))?;

    let hostname = parsed_url
        .host_str()
        .ok_or_else(|| KoavaError::invalid_input("Invalid server URL: missing hostname"))?
        .to_string();

    let port = parsed_url.port().unwrap_or(443);

    let verifier = PinnedKeyVerifier::new(server_public_key.to_string())?;

    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    let stream = tokio::net::TcpStream::connect(&format!("{}:{}", hostname, port))
        .await
        .map_err(|_| {
            KoavaError::invalid_input(&format!("Unable to connect to server at {}", hostname))
        })?;

    let hostname_for_error = hostname.clone();
    let dns_name = rustls::pki_types::ServerName::DnsName(
        rustls::pki_types::DnsName::try_from(hostname)
            .map_err(|_| KoavaError::invalid_input("Invalid DNS name for SNI"))?,
    );

    match connector.connect(dns_name, stream).await {
        Ok(_tls_stream) => Ok(()),
        Err(e) => {
            #[cfg(debug_assertions)]
            {
                eprintln!("[koalavault] Certificate/public key verification failed for {}: {:?}, but continuing in debug mode", hostname_for_error, e);
                return Ok(());
            }

            #[cfg(not(debug_assertions))]
            {
                let error_msg = if e.to_string().contains("ApplicationVerificationFailure") {
                    "Server validation failed"
                } else {
                    "Unable to establish secure connection"
                };
                return Err(KoavaError::invalid_input(error_msg));
            }
        }
    }
}

/// Validate certificate pinning configuration
#[cfg(feature = "cert-pinning")]
pub fn validate_certificate_pinning(server_public_key: &str) -> Result<()> {
    if server_public_key.is_empty() {
        return Err(KoavaError::invalid_input("Invalid server configuration"));
    }
    Ok(())
}

#[cfg(not(feature = "cert-pinning"))]
#[allow(dead_code)] // Used in config.rs when feature is enabled
pub fn validate_certificate_pinning(_server_public_key: &str) -> Result<()> {
    Ok(())
}

// Certificate pinning implementation

#[cfg(feature = "cert-pinning")]
#[derive(Debug)]
struct PinnedKeyVerifier {
    pinned_public_key: String,
    standard_verifier: Arc<rustls::client::WebPkiServerVerifier>,
}

#[cfg(feature = "cert-pinning")]
impl PinnedKeyVerifier {
    fn new(pinned_public_key: String) -> Result<Self> {
        let roots = Arc::new(webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect());

        let standard_verifier = rustls::client::WebPkiServerVerifier::builder(roots)
            .build()
            .map_err(|_| KoavaError::invalid_input("Failed to create certificate verifier"))?;

        Ok(Self {
            pinned_public_key,
            standard_verifier,
        })
    }

    fn extract_public_key_spki(cert: &CertificateDer) -> Result<Vec<u8>> {
        use x509_parser::prelude::*;

        let cert_bytes = cert.as_ref();
        let (_, parsed_cert) = X509Certificate::from_der(cert_bytes).map_err(|e| {
            KoavaError::invalid_input(&format!("Failed to parse certificate: {}", e))
        })?;

        let spki = parsed_cert.tbs_certificate.subject_pki;
        let spki_der = spki.raw;

        Ok(spki_der.to_vec())
    }

    fn verify_pinned_key(&self, cert: &CertificateDer) -> Result<()> {
        use sha2::{Digest, Sha256};

        let server_spki = Self::extract_public_key_spki(cert)?;

        let pinned_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.pinned_public_key)
            .map_err(|_| KoavaError::invalid_input("Invalid pinned public key format"))?;

        let server_spki_hash = Sha256::digest(&server_spki);

        if pinned_key_bytes.len() == server_spki.len() && pinned_key_bytes == server_spki {
            return Ok(());
        }

        if pinned_key_bytes.len() == 32
            && pinned_key_bytes.as_slice() == server_spki_hash.as_slice()
        {
            return Ok(());
        }

        let pinned_key_hash = Sha256::digest(&pinned_key_bytes);
        if pinned_key_hash.as_slice() == server_spki_hash.as_slice() {
            return Ok(());
        }

        Err(KoavaError::invalid_input("Public key mismatch"))
    }
}

#[cfg(feature = "cert-pinning")]
impl ServerCertVerifier for PinnedKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        match self.verify_pinned_key(end_entity) {
            Ok(_) => self.standard_verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ),
            Err(_) => {
                #[cfg(debug_assertions)]
                {
                    eprintln!("[koalavault] Public key pinning check failed, but continuing in debug mode");
                    return self.standard_verifier.verify_server_cert(
                        end_entity,
                        intermediates,
                        server_name,
                        ocsp_response,
                        now,
                    );
                }

                #[cfg(not(debug_assertions))]
                {
                    return Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    ));
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.standard_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.standard_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.standard_verifier.supported_verify_schemes()
    }
}
