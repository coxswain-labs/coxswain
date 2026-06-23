//! Trust-bundle publisher: watches the CA Secret and keeps the
//! `coxswain-discovery-trust` ConfigMap in sync.
//!
//! The controller is the sole writer of the trust ConfigMap (per the
//! controller-sole-diagnostic-emitter crate charter). The proxy mounts it
//! read-only via the kubelet — no API verbs required on the proxy SA.
//!
//! # Lifecycle
//!
//! 1. On startup, publish the current trust bundle immediately.
//! 2. Poll the CA Secret every 30 s; on a cert change, hot-reload
//!    [`CertAuthority`] and re-publish the bundle.
//!
//! A failed ConfigMap patch is logged as a warning — it does not panic or abort
//! the controller. Proxies that fail to read the ConfigMap will be unable to
//! bootstrap until the next successful publish.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{ObjectMeta, Patch, PatchParams};
use kube::{Api, Client};
use tracing::{info, warn};

use coxswain_core::identity::SvidIssuer;

use super::ca::CertAuthority;

// ── constants ─────────────────────────────────────────────────────────────────

/// Name of the trust-bundle ConfigMap written by this publisher.
pub const TRUST_BUNDLE_CM_NAME: &str = "coxswain-discovery-trust";

const FIELD_MANAGER: &str = "coxswain-controller";
const POLL_INTERVAL: Duration = Duration::from_secs(30);

// ── spawn_trust_publisher ─────────────────────────────────────────────────────

/// Spawn a background task that keeps the trust-bundle ConfigMap up to date.
///
/// Publishes immediately on first call, then polls every 30 s.  When the CA
/// Secret rotates, calls [`CertAuthority::reload`] and re-publishes.
///
/// The returned [`tokio::task::JoinHandle`] should be held for the process
/// lifetime.
pub fn spawn_trust_publisher(
    client: Client,
    authority: Arc<CertAuthority>,
    secret_name: String,
    namespace: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_publisher(client, authority, secret_name, namespace))
}

// ── internals ─────────────────────────────────────────────────────────────────

async fn run_publisher(
    client: Client,
    authority: Arc<CertAuthority>,
    secret_name: String,
    namespace: String,
) {
    // Publish the initial trust bundle before the first poll cycle.
    publish_trust_bundle(&client, &authority, &namespace).await;
    let mut last_cert: Vec<u8> = authority.trust_bundle();

    loop {
        tokio::time::sleep(POLL_INTERVAL).await;

        let api: Api<k8s_openapi::api::core::v1::Secret> =
            Api::namespaced(client.clone(), &namespace);
        let secret = match api.get(&secret_name).await {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    error = %e,
                    secret = %secret_name,
                    "trust publisher: failed to read CA Secret; retrying next cycle"
                );
                continue;
            }
        };

        let data = match secret.data.as_ref() {
            Some(d) => d,
            None => {
                warn!(secret = %secret_name, "trust publisher: CA Secret has no data");
                continue;
            }
        };

        let cert_pem = match data.get("tls.crt") {
            Some(b) => b.0.clone(),
            None => {
                warn!(secret = %secret_name, "trust publisher: CA Secret missing 'tls.crt'");
                continue;
            }
        };
        let key_pem = match data.get("tls.key") {
            Some(b) => b.0.clone(),
            None => {
                warn!(secret = %secret_name, "trust publisher: CA Secret missing 'tls.key'");
                continue;
            }
        };

        if last_cert != cert_pem {
            match authority.reload(&cert_pem, &key_pem) {
                Ok(()) => {
                    info!(
                        secret = %secret_name,
                        "trust publisher: CA hot-reloaded after Secret rotation"
                    );
                    last_cert = cert_pem;
                    publish_trust_bundle(&client, &authority, &namespace).await;
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "trust publisher: CA reload failed; retaining current CA"
                    );
                }
            }
        }
    }
}

/// SSA-patch the `coxswain-discovery-trust` ConfigMap with the current CA bundle.
async fn publish_trust_bundle(client: &Client, authority: &CertAuthority, namespace: &str) {
    let bundle = authority.trust_bundle();
    let bundle_str = match String::from_utf8(bundle) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                error = %e,
                "trust publisher: CA bundle is not valid UTF-8; skipping publish"
            );
            return;
        }
    };

    let cm = ConfigMap {
        metadata: ObjectMeta {
            name: Some(TRUST_BUNDLE_CM_NAME.to_owned()),
            namespace: Some(namespace.to_owned()),
            ..Default::default()
        },
        data: Some(BTreeMap::from([("ca.crt".to_owned(), bundle_str)])),
        ..Default::default()
    };

    let api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let params = PatchParams::apply(FIELD_MANAGER).force();
    match api
        .patch(TRUST_BUNDLE_CM_NAME, &params, &Patch::Apply(&cm))
        .await
    {
        Ok(_) => info!(namespace, "trust publisher: trust bundle ConfigMap updated"),
        Err(e) => warn!(
            error = %e,
            namespace,
            "trust publisher: failed to patch trust bundle ConfigMap"
        ),
    }
}
