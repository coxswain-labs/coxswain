//! SNI-driven certificate selector for the Pingora TLS listener.

use async_trait::async_trait;
use coxswain_core::tls::SharedTlsStore;
use pingora_core::listeners::TlsAccept;
use pingora_core::protocols::tls::TlsRef;
use pingora_core::tls::{ext, pkey::PKey, ssl::NameType, x509::X509};

/// SNI-driven certificate selector for the Pingora TLS listener.
///
/// Loaded on every TLS handshake from the live [`SharedTlsStore`] — no locks,
/// no channels. If no cert matches the client's SNI, the handshake is allowed
/// to fail naturally (OpenSSL/BoringSSL sends `unrecognized_name`).
pub struct SniCertSelector {
    tls: SharedTlsStore,
}

impl SniCertSelector {
    /// Wrap a [`SharedTlsStore`] in an SNI certificate selector.
    pub fn new(tls: SharedTlsStore) -> Self {
        Self { tls }
    }
}

#[async_trait]
impl TlsAccept for SniCertSelector {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        // Clone immediately to drop the immutable borrow before the mutable
        // ssl_use_certificate / ssl_use_private_key calls below.
        let Some(sni) = ssl.servername(NameType::HOST_NAME).map(str::to_owned) else {
            tracing::debug!("TLS handshake with no SNI — no cert installed");
            return;
        };

        let store = self.tls.load();
        let Some(cert) = store.find_cert(&sni) else {
            tracing::debug!(sni, "No TLS cert for SNI — handshake will fail");
            return;
        };

        let x509 = match X509::from_pem(&cert.cert_pem) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(sni, source = %cert.source, error = %e, "cert PEM parse failed");
                return;
            }
        };
        let pkey = match PKey::private_key_from_pem(&cert.key_pem) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(sni, source = %cert.source, error = %e, "key PEM parse failed");
                return;
            }
        };
        if let Err(e) = ext::ssl_use_certificate(ssl, &x509) {
            tracing::warn!(sni, error = %e, "ssl_use_certificate failed");
            return;
        }
        if let Err(e) = ext::ssl_use_private_key(ssl, &pkey) {
            tracing::warn!(sni, error = %e, "ssl_use_private_key failed");
        }
    }
}
