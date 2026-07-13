//! `CertAuthority` — controller-side CA: load, sign SVIDs, and self-issue server certs.
//!
//! This module owns the CA lifecycle:
//!
//! - **Loading**: parse PEM cert+key from a Kubernetes Secret (via [`super::store`]).
//! - **Signing**: produce short-lived SVIDs from a CSR (implements
//!   [`coxswain_core::SvidIssuer`]).
//! - **Self-issuance**: generate the controller's own server SVID (and key) so
//!   the discovery and bootstrap listeners can present a valid SPIFFE cert.
//! - **Trust-bundle**: return the public root(s) as PEM so the publisher can
//!   write them to the trust-bundle ConfigMap.
//! - **Generation**: create a fresh self-signed CA keypair when `mode=auto` and
//!   no Secret exists yet.
//!
//! The CA cert and key are stored in a [`coxswain_core::Shared`] cell so
//! hot-reload on Secret change is lock-free on the read path.

use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use thiserror::Error;
use time::OffsetDateTime;

use coxswain_core::Shared;
use coxswain_core::identity::{CsrPem, IssuedSvid, IssuerError, SpiffeId, SvidIssuer};

// ── CaError ───────────────────────────────────────────────────────────────────

/// Error produced by [`CertAuthority`] operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CaError {
    /// The PEM bytes are not a valid certificate or key.
    #[error("invalid PEM: {0}")]
    InvalidPem(String),
    /// An rcgen keypair generation or signing failure.
    #[error("rcgen error: {0}")]
    Rcgen(String),
    /// The CSR PEM is malformed or cannot be parsed.
    #[error("malformed CSR: {0}")]
    MalformedCsr(String),
}

// ── IssuedServerSvid ──────────────────────────────────────────────────────────

/// A freshly self-issued server SVID (cert + private key + not_after).
///
/// Used to configure the discovery and bootstrap listeners with a valid SPIFFE
/// server certificate signed by the controller's own CA.
// intentionally open: field-literal used in bin wiring
pub struct IssuedServerSvid {
    /// PEM-encoded server certificate.
    pub cert_pem: Vec<u8>,
    /// PEM-encoded private key (stays inside the controller process).
    pub key_pem: Vec<u8>,
    /// SVID expiry as Unix seconds (UTC).
    pub not_after_unix: i64,
}

// ── CaInner ───────────────────────────────────────────────────────────────────

/// Inner CA state, behind a [`Shared`] cell for lock-free hot-reload.
struct CaInner {
    /// Raw CA cert PEM stored for the trust-bundle export.
    ca_cert_pem: Vec<u8>,
    /// rcgen `Issuer` (cert + key), used to sign leaf certificates.
    issuer: Issuer<'static, KeyPair>,
    /// Default SVID TTL — set at load time from the configured value.
    svid_ttl: Duration,
}

// ── CertAuthority ─────────────────────────────────────────────────────────────

/// The controller's certificate authority.
///
/// Thread-safe: `Shared<CaInner>` wraps an `ArcSwap` cell so signing and
/// trust-bundle reads are a single atomic pointer load.  A background task
/// (driven by [`super::store`]) calls `reload()` when the CA
/// Secret changes; running streams see the new CA on their next sign call.
#[non_exhaustive]
pub struct CertAuthority {
    inner: Shared<CaInner>,
}

impl CertAuthority {
    /// Load a `CertAuthority` from PEM cert and key bytes.
    ///
    /// `svid_ttl` is the lifetime for SVIDs signed by this CA.
    ///
    /// # Errors
    ///
    /// Returns [`CaError`] if the PEM cannot be parsed.
    #[must_use = "loading the CA may fail; use the Result"]
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8], svid_ttl: Duration) -> Result<Self, CaError> {
        let inner = load_inner(cert_pem, key_pem, svid_ttl)?;
        Ok(Self {
            inner: Shared::from_value(inner),
        })
    }

    /// Generate a fresh self-signed CA keypair and return the PEM bytes.
    ///
    /// The returned bytes are stored in the CA Secret so all controller
    /// replicas converge on the same CA.
    ///
    /// # Errors
    ///
    /// Returns [`CaError`] if rcgen fails to generate the keypair.
    #[must_use = "generation may fail; use the Result"]
    pub fn generate() -> Result<(Vec<u8>, Vec<u8>), CaError> {
        let key = KeyPair::generate().map_err(|e| CaError::Rcgen(e.to_string()))?;
        let mut params =
            CertificateParams::new(vec![]).map_err(|e| CaError::Rcgen(e.to_string()))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, "coxswain-discovery-ca");
        // CA validity: 10 years
        params.not_after = OffsetDateTime::now_utc() + time::Duration::days(3_650);

        let cert = params
            .self_signed(&key)
            .map_err(|e| CaError::Rcgen(e.to_string()))?;

        Ok((cert.pem().into_bytes(), key.serialize_pem().into_bytes()))
    }

    /// Hot-reload the CA from new PEM bytes.
    ///
    /// After this call, new signing operations use the new CA.  On error
    /// the old CA remains active.
    ///
    /// # Errors
    ///
    /// Returns [`CaError`] if the PEM cannot be parsed.
    #[must_use = "reload may fail; use the Result to detect PEM parse errors"]
    pub fn reload(&self, cert_pem: &[u8], key_pem: &[u8]) -> Result<(), CaError> {
        let old_ttl = self.inner.load().svid_ttl;
        let inner = load_inner(cert_pem, key_pem, old_ttl)?;
        self.inner.store(Arc::new(inner));
        Ok(())
    }

    /// Issue a server SVID for the controller itself (for the discovery/bootstrap
    /// listeners).  The private key stays inside the controller process.
    ///
    /// # Errors
    ///
    /// Returns [`CaError`] if key generation or signing fails.
    #[must_use = "the issued SVID is the caller's credential; dropping it silently is a bug"]
    pub fn self_issue_server(
        &self,
        id: &SpiffeId,
        ttl: Duration,
    ) -> Result<IssuedServerSvid, CaError> {
        let key = KeyPair::generate().map_err(|e| CaError::Rcgen(e.to_string()))?;
        let inner = self.inner.load();
        let cert_pem = sign_leaf(&inner.issuer, &key, id, ttl)?;
        let not_after_unix = not_after_unix_from_ttl(ttl);
        Ok(IssuedServerSvid {
            cert_pem,
            key_pem: key.serialize_pem().into_bytes(),
            not_after_unix,
        })
    }
}

impl SvidIssuer for CertAuthority {
    fn sign_csr(&self, csr: &CsrPem, id: &SpiffeId) -> Result<IssuedSvid, IssuerError> {
        let inner = self.inner.load();

        // Parse the CSR PEM.
        let csr_str = std::str::from_utf8(csr.as_bytes())
            .map_err(|e| IssuerError::MalformedCsr(e.to_string()))?;
        let mut csr_params = CertificateSigningRequestParams::from_pem(csr_str)
            .map_err(|e| IssuerError::MalformedCsr(e.to_string()))?;

        let ttl = inner.svid_ttl;
        let not_after_unix = not_after_unix_from_ttl(ttl);

        // Override SANs on the CSR params: the authoritative identity comes from
        // the authenticated token, not what the proxy put in the CSR.
        let uri_san: SanType = SanType::URI(
            id.as_str()
                .try_into()
                .map_err(|e| IssuerError::Signing(format!("invalid URI SAN: {e}")))?,
        );
        csr_params.params.subject_alt_names = vec![uri_san];
        csr_params.params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        csr_params.params.not_after = OffsetDateTime::now_utc()
            + time::Duration::try_from(ttl)
                .map_err(|e| IssuerError::Signing(format!("invalid TTL: {e}")))?;

        let cert = csr_params
            .signed_by(&inner.issuer)
            .map_err(|e| IssuerError::Signing(e.to_string()))?;

        Ok(IssuedSvid {
            cert_pem: cert.pem().into_bytes(),
            not_after_unix,
        })
    }

    fn trust_bundle(&self) -> Vec<u8> {
        self.inner.load().ca_cert_pem.clone()
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Parse PEM cert + key into a [`CaInner`].
fn load_inner(cert_pem: &[u8], key_pem: &[u8], svid_ttl: Duration) -> Result<CaInner, CaError> {
    let cert_str = std::str::from_utf8(cert_pem).map_err(|e| CaError::InvalidPem(e.to_string()))?;
    let key_str = std::str::from_utf8(key_pem).map_err(|e| CaError::InvalidPem(e.to_string()))?;

    let key = KeyPair::from_pem(key_str).map_err(|e| CaError::Rcgen(e.to_string()))?;
    let issuer =
        Issuer::from_ca_cert_pem(cert_str, key).map_err(|e| CaError::Rcgen(e.to_string()))?;

    Ok(CaInner {
        ca_cert_pem: cert_pem.to_vec(),
        issuer,
        svid_ttl,
    })
}

/// Sign a leaf certificate for self-issuance of server SVIDs.
fn sign_leaf(
    issuer: &Issuer<KeyPair>,
    key: &KeyPair,
    id: &SpiffeId,
    ttl: Duration,
) -> Result<Vec<u8>, CaError> {
    let uri_san: SanType = SanType::URI(
        id.as_str()
            .try_into()
            .map_err(|e| CaError::Rcgen(format!("invalid URI SAN: {e}")))?,
    );
    let mut params = CertificateParams::new(vec![]).map_err(|e| CaError::Rcgen(e.to_string()))?;
    params.subject_alt_names = vec![uri_san];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_after = OffsetDateTime::now_utc()
        + time::Duration::try_from(ttl).map_err(|e| CaError::Rcgen(format!("invalid TTL: {e}")))?;

    let cert = params
        .signed_by(key, issuer)
        .map_err(|e| CaError::Rcgen(e.to_string()))?;

    Ok(cert.pem().into_bytes())
}

/// Compute the `not_after` Unix timestamp (seconds) for a given TTL.
fn not_after_unix_from_ttl(ttl: Duration) -> i64 {
    let now = OffsetDateTime::now_utc();
    let expiry = now + time::Duration::try_from(ttl).unwrap_or(time::Duration::seconds(86_400));
    expiry.unix_timestamp()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use rcgen::{CertificateParams, KeyPair, SanType};
    use x509_parser::prelude::*;

    use coxswain_core::identity::CsrPem;

    fn gen_test_ca() -> (Vec<u8>, Vec<u8>) {
        CertAuthority::generate().expect("generate CA")
    }

    fn gen_csr(spiffe_uri: &str) -> CsrPem {
        let key = KeyPair::generate().expect("csr key");
        let san = SanType::URI(spiffe_uri.try_into().expect("uri san"));
        let mut params = CertificateParams::new(vec![]).expect("params");
        params.subject_alt_names = vec![san];
        let pem = params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("csr pem")
            .into_bytes();
        CsrPem::new(pem)
    }

    #[test]
    fn generate_returns_valid_pem() {
        let (cert, key) = gen_test_ca();
        assert!(std::str::from_utf8(&cert).unwrap().contains("CERTIFICATE"));
        assert!(std::str::from_utf8(&key).unwrap().contains("PRIVATE KEY"));
    }

    #[test]
    fn from_pem_roundtrips() {
        let (cert, key) = gen_test_ca();
        CertAuthority::from_pem(&cert, &key, Duration::from_secs(3_600)).expect("load CA");
    }

    #[test]
    fn trust_bundle_returns_ca_cert() {
        let (cert, key) = gen_test_ca();
        let ca = CertAuthority::from_pem(&cert, &key, Duration::from_secs(3_600)).expect("load CA");
        let bundle = ca.trust_bundle();
        assert_eq!(bundle, cert);
    }

    #[test]
    fn sign_csr_sets_spiffe_uri_san() {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;

        let (cert_pem, key_pem) = gen_test_ca();
        let ca = CertAuthority::from_pem(&cert_pem, &key_pem, Duration::from_secs(3_600))
            .expect("load CA");

        let id = SpiffeId::from_parts("cluster.local", "coxswain-system", "coxswain-proxy");
        let csr = gen_csr(id.as_str());

        let svid = ca.sign_csr(&csr, &id).expect("sign CSR");
        assert!(!svid.cert_pem.is_empty());
        assert!(svid.not_after_unix > 0);

        // Parse and verify the URI SAN.
        let der: CertificateDer<'_> =
            CertificateDer::from_pem_slice(&svid.cert_pem).expect("parse DER");
        let (_, parsed) = parse_x509_certificate(der.as_ref()).expect("parse x509");
        let san_ext = parsed
            .subject_alternative_name()
            .expect("san extension result")
            .expect("san extension present");
        let uris: Vec<_> = san_ext
            .value
            .general_names
            .iter()
            .filter_map(|n| {
                if let GeneralName::URI(u) = n {
                    Some(*u)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            uris,
            vec![id.as_str()],
            "URI SAN must match the authenticated SPIFFE ID"
        );
    }

    #[test]
    fn self_issue_server_returns_cert_and_key() {
        let (cert, key) = gen_test_ca();
        let ca = CertAuthority::from_pem(&cert, &key, Duration::from_secs(3_600)).expect("load CA");
        let id = SpiffeId::from_parts("cluster.local", "coxswain-system", "coxswain-controller");
        let svid = ca
            .self_issue_server(&id, Duration::from_secs(3_600))
            .expect("self-issue");
        assert!(!svid.cert_pem.is_empty());
        assert!(!svid.key_pem.is_empty());
        assert!(svid.not_after_unix > 0);
    }

    #[test]
    fn reload_updates_trust_bundle() {
        let (cert1, key1) = gen_test_ca();
        let ca =
            CertAuthority::from_pem(&cert1, &key1, Duration::from_secs(3_600)).expect("load CA");

        let (cert2, key2) = gen_test_ca();
        ca.reload(&cert2, &key2).expect("reload CA");

        let bundle = ca.trust_bundle();
        assert_ne!(bundle, cert1, "bundle should change after reload");
    }

    #[test]
    fn sign_csr_overrides_san_with_authenticated_id() {
        let (cert_pem, key_pem) = gen_test_ca();
        let ca = CertAuthority::from_pem(&cert_pem, &key_pem, Duration::from_secs(3_600))
            .expect("load CA");

        // CSR has a different SPIFFE ID from the token-authenticated one.
        let csr_id = "spiffe://cluster.local/ns/coxswain-system/sa/coxswain-proxy";
        let token_id =
            SpiffeId::from_parts("cluster.local", "coxswain-system", "coxswain-controller");
        let csr = gen_csr(csr_id);

        let svid = ca.sign_csr(&csr, &token_id).expect("sign CSR");

        // The issued cert must carry the *token*-authenticated ID, not the CSR's ID.
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;
        let der = CertificateDer::from_pem_slice(&svid.cert_pem).expect("parse DER");
        let (_, parsed) = parse_x509_certificate(der.as_ref()).expect("parse x509");
        let san_ext = parsed
            .subject_alternative_name()
            .expect("san extension result")
            .expect("san present");
        let uris: Vec<_> = san_ext
            .value
            .general_names
            .iter()
            .filter_map(|n| {
                if let GeneralName::URI(u) = n {
                    Some(*u)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            uris,
            vec![token_id.as_str()],
            "CA must override the CSR SAN with the token-authenticated identity"
        );
    }
}
