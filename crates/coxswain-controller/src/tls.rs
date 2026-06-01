use coxswain_core::tls::TlsCert;
use k8s_openapi::api::core::v1::Secret;
use kube::runtime::reflector;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum TlsLoadError {
    #[error("Secret not found in store")]
    NotFound,
    #[error("Secret has type {0:?}, expected 'kubernetes.io/tls'")]
    WrongType(String),
    #[error("Secret is missing 'tls.crt' key")]
    MissingCert,
    #[error("Secret is missing 'tls.key' key")]
    MissingKey,
}

/// Look up a `kubernetes.io/tls` Secret by namespace/name from the reflector
/// store and extract the PEM bytes. PEM validity is checked by the proxy's
/// SNI callback on each handshake; invalid bytes produce a warning there.
pub(crate) fn load_tls_cert(
    ns: &str,
    name: &str,
    store: &reflector::Store<Secret>,
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

    Ok(TlsCert::new(cert_pem, key_pem, format!("{ns}/{name}")))
}
