//! `CaStore` — load or generate the CA Secret via the Kubernetes API.
//!
//! On startup every controller replica reads the configured CA Secret:
//!
//! - **Present**: load into [`CertAuthority`] and return.
//! - **Absent + `mode=auto`**: generate a fresh CA and `create` the Secret.
//!   Creation is race-free without leader election: the first replica to
//!   `create` wins; any replica that loses the race gets `409 AlreadyExists`,
//!   loops back, and loads the winner.  No `force`-apply, so two replicas
//!   generating distinct CAs can never flip-flop the stored bytes.
//! - **Absent + `mode=external`**: return an error (fail closed — the operator
//!   must supply the Secret before deploying).
//!
//! Deliberately independent of leader election: CA acquisition runs before the
//! leader lease is settled (the bootstrap/stream TLS listeners need the CA at
//! startup), so gating on the in-process leader flag would deadlock every
//! replica behind an election that has not happened yet.
//!
//! [`CertAuthority`]: super::ca::CertAuthority

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{ObjectMeta, PostParams};
use kube::{Api, Client};
use thiserror::Error;
use tracing::info;

use super::ca::{CaError, CertAuthority};

// ── CaMode ────────────────────────────────────────────────────────────────────

/// How the controller acquires its CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaMode {
    /// Generate a fresh self-signed CA if the Secret is absent.
    Auto,
    /// Require a pre-existing Secret; fail closed if absent.
    External,
}

// ── CaStoreError ──────────────────────────────────────────────────────────────

/// Error loading or initialising the CA Secret.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CaStoreError {
    /// A Kubernetes API call failed.
    #[error("kubernetes API error: {0}")]
    Api(#[source] kube::Error),
    /// The Secret exists but is missing the expected PEM fields.
    #[error("CA Secret missing required fields ('tls.crt' and 'tls.key')")]
    MissingFields,
    /// `mode=external` was configured but no Secret exists.
    #[error("CA Secret absent and mode=external; operator must supply the Secret before deploying")]
    ExternalMissing,
    /// The PEM bytes in the Secret are not a valid CA cert+key.
    #[error("CA certificate error: {0}")]
    Ca(#[source] CaError),
}

// ── internal constants ─────────────────────────────────────────────────────────

const RACE_RETRY_INTERVAL: Duration = Duration::from_millis(250);

// ── helpers ───────────────────────────────────────────────────────────────────

/// Extract `tls.crt` and `tls.key` bytes from a Kubernetes Secret.
fn extract_pem(secret: &Secret) -> Result<(Vec<u8>, Vec<u8>), CaStoreError> {
    let data = secret.data.as_ref().ok_or(CaStoreError::MissingFields)?;
    let cert = data.get("tls.crt").ok_or(CaStoreError::MissingFields)?;
    let key = data.get("tls.key").ok_or(CaStoreError::MissingFields)?;
    Ok((cert.0.clone(), key.0.clone()))
}

/// Outcome of attempting to `create` the freshly generated CA Secret.
enum CreateOutcome {
    /// This replica won the race; the generated CA is now the stored CA.
    Created,
    /// Another replica created the Secret first; the caller must re-read it.
    AlreadyExists,
}

/// `create` (POST) the CA Secret with the given cert+key PEM.
///
/// Uses `create`, not server-side apply: the first replica to POST wins, and a
/// loser receives `409 AlreadyExists` (mapped to [`CreateOutcome::AlreadyExists`])
/// so it re-reads the winner instead of force-overwriting with its own CA.
async fn create_ca_secret(
    client: &Client,
    secret_name: &str,
    namespace: &str,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<CreateOutcome, CaStoreError> {
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.to_owned()),
            namespace: Some(namespace.to_owned()),
            ..Default::default()
        },
        type_: Some("Opaque".to_owned()),
        data: Some(BTreeMap::from([
            ("tls.crt".to_owned(), ByteString(cert_pem.to_vec())),
            ("tls.key".to_owned(), ByteString(key_pem.to_vec())),
        ])),
        ..Default::default()
    };

    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    match api.create(&PostParams::default(), &secret).await {
        Ok(_) => {
            info!(secret = secret_name, namespace, "CA Secret created");
            Ok(CreateOutcome::Created)
        }
        Err(kube::Error::Api(e)) if e.code == 409 => {
            info!(
                secret = secret_name,
                namespace, "CA Secret already created by another replica; reloading winner"
            );
            Ok(CreateOutcome::AlreadyExists)
        }
        Err(e) => Err(CaStoreError::Api(e)),
    }
}

// ── load_or_generate ──────────────────────────────────────────────────────────

/// Load the CA from the named Secret, or generate and create it when absent.
///
/// The returned [`CertAuthority`] is ready to sign SVIDs. The caller should
/// then pass it to [`super::publisher::spawn_trust_publisher`] so the trust
/// bundle is published to the ConfigMap before proxies try to bootstrap.
///
/// Race-free across replicas without leader election: `mode=auto` generates and
/// `create`s the Secret, and a `409 AlreadyExists` loser re-reads the winner.
///
/// # Errors
///
/// Returns [`CaStoreError`] on API errors, PEM parse failures, or when the
/// Secret is absent in `external` mode.
pub async fn load_or_generate(
    client: &Client,
    secret_name: &str,
    namespace: &str,
    mode: CaMode,
    svid_ttl: Duration,
) -> Result<Arc<CertAuthority>, CaStoreError> {
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);

    loop {
        match api.get(secret_name).await {
            Ok(secret) => {
                let (cert_pem, key_pem) = extract_pem(&secret)?;
                let authority = CertAuthority::from_pem(&cert_pem, &key_pem, svid_ttl)
                    .map_err(CaStoreError::Ca)?;
                info!(
                    secret = secret_name,
                    namespace, "CA loaded from Kubernetes Secret"
                );
                return Ok(Arc::new(authority));
            }

            Err(kube::Error::Api(ref e)) if e.code == 404 => match mode {
                CaMode::External => return Err(CaStoreError::ExternalMissing),
                CaMode::Auto => {
                    info!(
                        secret = secret_name,
                        namespace, "CA Secret absent; generating self-signed CA (mode=auto)"
                    );
                    let (cert_pem, key_pem) =
                        CertAuthority::generate().map_err(CaStoreError::Ca)?;
                    match create_ca_secret(client, secret_name, namespace, &cert_pem, &key_pem)
                        .await?
                    {
                        CreateOutcome::Created => {
                            let authority = CertAuthority::from_pem(&cert_pem, &key_pem, svid_ttl)
                                .map_err(CaStoreError::Ca)?;
                            return Ok(Arc::new(authority));
                        }
                        // Lost the create race: brief pause, then re-GET the winner.
                        CreateOutcome::AlreadyExists => {
                            tokio::time::sleep(RACE_RETRY_INTERVAL).await;
                        }
                    }
                }
            },

            Err(e) => return Err(CaStoreError::Api(e)),
        }
    }
}
