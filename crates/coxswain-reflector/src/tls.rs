//! TLS certificate load helpers for Gateway listener Secrets.

use crate::MergedStore;
use coxswain_core::tls::{KeyAlgorithm, TlsCert};
use k8s_openapi::api::core::v1::Secret;
use kube::runtime::reflector;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum TlsLoadError {
    #[error("secret not found in store")]
    NotFound,
    #[error("secret has type {0:?}, expected 'kubernetes.io/tls'")]
    WrongType(String),
    #[error("secret is missing 'tls.crt' key")]
    MissingCert,
    #[error("secret is missing 'tls.key' key")]
    MissingKey,
    #[error("secret TLS data is not valid PEM")]
    InvalidPem,
}

/// Look up a `kubernetes.io/tls` Secret by namespace/name from the reflector
/// store and extract the PEM bytes. Both cert and key data must contain a PEM
/// header (`-----BEGIN`) to be considered valid.
///
/// # Errors
///
/// Returns [`TlsLoadError::NotFound`] if the Secret is not in the store,
/// [`TlsLoadError::WrongType`] if its `type` is not `kubernetes.io/tls`,
/// [`TlsLoadError::MissingCert`] if `tls.crt` is absent,
/// [`TlsLoadError::MissingKey`] if `tls.key` is absent, or
/// [`TlsLoadError::InvalidPem`] if either field lacks a `-----BEGIN` header.
#[must_use = "TLS certificate load result must be handled"]
pub(crate) fn load_tls_cert(
    ns: &str,
    name: &str,
    store: &MergedStore<Secret>,
) -> Result<TlsCert, TlsLoadError> {
    let key = reflector::ObjectRef::<Secret>::new(name).within(ns);
    let secret = store.get(&key).ok_or(TlsLoadError::NotFound)?;

    let secret_type = secret.type_.as_deref().unwrap_or("");
    if secret_type != "kubernetes.io/tls" {
        return Err(TlsLoadError::WrongType(secret_type.to_string()));
    }

    let data = secret.data.as_ref().ok_or(TlsLoadError::MissingCert)?;
    let cert_pem = data
        .get("tls.crt")
        .ok_or(TlsLoadError::MissingCert)?
        .0
        .clone();
    let key_pem = data
        .get("tls.key")
        .ok_or(TlsLoadError::MissingKey)?
        .0
        .clone();

    if !cert_pem.windows(10).any(|w| w == b"-----BEGIN") {
        return Err(TlsLoadError::InvalidPem);
    }
    if !key_pem.windows(10).any(|w| w == b"-----BEGIN") {
        return Err(TlsLoadError::InvalidPem);
    }

    let (not_after, key_algorithm) = parse_leaf_cert_metadata(&cert_pem).unwrap_or_else(|e| {
        tracing::warn!(
            ns,
            name,
            error = %e,
            "TLS cert parse failed — expiry metric will omit this cert, algorithm defaults to Other"
        );
        (None, KeyAlgorithm::Other)
    });

    Ok(TlsCert::new(cert_pem, key_pem, format!("{ns}/{name}"))
        .with_not_after(not_after)
        .with_key_algorithm(key_algorithm))
}

/// Parse the leaf certificate's `notAfter` field and SPKI key algorithm in a
/// single parse pass.
///
/// Returns `Ok((None, Other))` if the chain parsed but contained no certificate
/// (a degenerate case — the expected shape for any well-formed
/// `kubernetes.io/tls` Secret is `Ok((Some(_), Rsa | Ecdsa))`). Returns `Err`
/// on PEM/ASN.1 parse failure.
fn parse_leaf_cert_metadata(
    cert_pem: &[u8],
) -> Result<(Option<std::time::SystemTime>, KeyAlgorithm), String> {
    use x509_parser::pem::Pem;
    use x509_parser::prelude::*;
    let mut reader = std::io::Cursor::new(cert_pem);
    let pem = Pem::read(&mut reader)
        .map_err(|e| format!("PEM parse: {e}"))?
        .0;
    let (_, cert) =
        parse_x509_certificate(&pem.contents).map_err(|e| format!("X509 parse: {e}"))?;

    let not_after_unix = cert.validity().not_after.timestamp();
    let not_after = if not_after_unix < 0 {
        None
    } else {
        // `timestamp()` is a Unix epoch i64; convert to SystemTime via Duration.
        u64::try_from(not_after_unix)
            .ok()
            .map(|s| std::time::UNIX_EPOCH + std::time::Duration::from_secs(s))
    };

    // SPKI key algorithm — match well-known OIDs by their dotted-decimal string.
    //
    // OIDs:
    //   rsaEncryption   1.2.840.113549.1.1.1  (RFC 3279)
    //   id-ecPublicKey  1.2.840.10045.2.1      (RFC 5480)
    let key_algorithm = match cert
        .tbs_certificate
        .subject_pki
        .algorithm
        .algorithm
        .to_string()
        .as_str()
    {
        "1.2.840.113549.1.1.1" => KeyAlgorithm::Rsa,
        "1.2.840.10045.2.1" => KeyAlgorithm::Ecdsa,
        _ => KeyAlgorithm::Other,
    };

    Ok((not_after, key_algorithm))
}
