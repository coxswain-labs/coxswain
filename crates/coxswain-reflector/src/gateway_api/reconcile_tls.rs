//! Gateway listener TLS resolution, extracted from `reconcile.rs`.
//!
//! Owns the cohesive TLS-material cluster the `GatewayApiReconciler::reconcile_tls`
//! orchestration in `reconcile.rs` delegates to:
//!
//! - [`GatewayTlsTarget`] — the per-Gateway parameter group.
//! - [`resolve_listener_tls`] — load an HTTPS/TLS-Terminate listener's
//!   `certificateRefs` (GEP-851) into the per-port TLS store, enforcing the
//!   cross-namespace ReferenceGrant.
//! - [`grants_for_source`] — pick the Gateway- vs ListenerSet-scoped grant set
//!   for a listener (GEP-1713).
//! - [`resolve_route_client_cert`] — resolve the GEP-3155 backend client cert a
//!   route inherits from its owned parent Gateways.

use crate::MergedStore;
use crate::gw_types::v::httproutes::HttpRouteParentRefs;
use crate::reconciler::listener_merge::EffectiveListener;
use crate::status::{ListenerReadiness, ListenerSource};
use crate::tls::load_tls_cert;
use coxswain_core::ownership::{ObjectKey, parent_ref_owned};
use coxswain_core::reference_grants::{self, ReferenceGrantKey};
use coxswain_core::routing::BackendClientCert;
use coxswain_core::tls::PortTlsStoreBuilder;
use k8s_openapi::api::core::v1::Secret;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Resolve the GEP-3155 backend client cert inherited by this route from its
/// owned parent Gateways.
///
/// Walks `parent_refs` in declaration order, skipping refs to non-owned Gateways.
/// Returns `(Some(cert), false)` for the first owned parent with a resolved cert,
/// `(None, true)` if the first owned parent with a cert ref failed to resolve it,
/// and `(None, false)` if no owned parent has any cert ref.
///
/// Declaration-order precedence is intentional: when a route is attached to multiple
/// owned Gateways with different certs, the first parentRef wins (the cert rides the
/// route's single shared `BackendGroup`, so per-parent divergence cannot be expressed).
pub(super) fn resolve_route_client_cert<'a>(
    parent_refs: &[HttpRouteParentRefs],
    route_ns: &str,
    owned_gateways: &HashSet<ObjectKey>,
    backend_client_certs: &'a HashMap<ObjectKey, Arc<BackendClientCert>>,
    backend_client_cert_failures: &HashSet<ObjectKey>,
) -> (Option<&'a Arc<BackendClientCert>>, bool) {
    for p in parent_refs {
        if !parent_ref_owned(
            p.group.as_deref(),
            p.kind.as_deref(),
            p.namespace.as_deref(),
            &p.name,
            route_ns,
            owned_gateways,
        ) {
            continue;
        }
        let key = ObjectKey::new(p.namespace.as_deref().unwrap_or(route_ns), p.name.as_str());
        if let Some(cc) = backend_client_certs.get(&key) {
            return (Some(cc), false);
        }
        if backend_client_cert_failures.contains(&key) {
            return (None, true);
        }
    }
    (None, false)
}

/// Per-Gateway context passed to [`super::GatewayApiReconciler::reconcile_tls`].
///
/// Groups the 7+ parameters into a single struct to satisfy the workspace
/// `clippy::too_many_arguments` policy.
pub(crate) struct GatewayTlsTarget<'a> {
    /// Gateway `metadata.name` — used in diagnostic log messages.
    pub(crate) gw_name: &'a str,
    /// Effective listeners for this Gateway (its own plus any merged ListenerSet
    /// listeners, GEP-1713).
    pub(crate) listeners: &'a [EffectiveListener],
    /// `listenerPort → internalPort` mapping.
    ///
    /// For the **shared reconciler**: built from VIP Services (#472). An absent
    /// entry (maps to 0 via `unwrap_or`) means the VIP Service has not yet been
    /// created — readiness is deferred (`VipPending`) until the next rebuild.
    ///
    /// For the **dedicated reconciler**: pre-populated with identity mappings
    /// (`spec_port → spec_port`) so `internal_port` is never 0. The dedicated
    /// proxy binds the spec port directly; treating 0 as "pending" would prevent
    /// the listener from ever reaching `TlsPassthrough` / `TlsTerminate`.
    pub(crate) internal_ports: &'a HashMap<u16, u16>,
}

/// Select the applicable ReferenceGrant set for a listener based on its source kind.
///
/// A `Gateway` listener's cross-namespace cert is permitted by `from.kind: Gateway` grants;
/// a `ListenerSet` listener's by `from.kind: ListenerSet` grants (GEP-1713).
pub(super) fn grants_for_source<'g>(
    source: &ListenerSource,
    cert_grants: &'g HashSet<ReferenceGrantKey>,
    ls_cert_grants: &'g HashSet<ReferenceGrantKey>,
) -> &'g HashSet<ReferenceGrantKey> {
    match source {
        ListenerSource::Gateway => cert_grants,
        ListenerSource::ListenerSet(_) => ls_cert_grants,
    }
}

/// Resolve an HTTPS / TLS-Terminate listener's `certificateRefs` and compute its
/// [`ListenerReadiness`].
///
/// `install_certs` decouples *ref validation* from the *cert install* side
/// effect: reference resolution (which yields `RefNotPermitted` /
/// `InvalidCertificateRef` / `Resolved`) always runs, because it drives the
/// `ResolvedRefs` condition and must not depend on VIP port allocation. When
/// `install_certs` is `false` — the caller has no allocated internal port yet
/// (`VipPending`) — a successfully-loaded cert is still counted (so the readiness
/// verdict is identical) but NOT added to `builder`, avoiding an install at the
/// wrong bind port; the next rebuild re-runs this with the real port and
/// `install_certs = true`. A terminal ref failure is returned regardless of
/// `install_certs` so the caller can surface it on `ResolvedRefs` immediately.
pub(super) fn resolve_listener_tls(
    gw_name: &str,
    listener: &EffectiveListener,
    secrets: &MergedStore<Secret>,
    cert_grants: &HashSet<ReferenceGrantKey>,
    builder: &mut PortTlsStoreBuilder,
    bind_port: u16,
    install_certs: bool,
) -> ListenerReadiness {
    // ListenerSet listeners resolve their certificateRefs in the ListenerSet's own
    // namespace (GEP-1713), not the parent Gateway's; Gateway listeners use the
    // Gateway namespace. Both are carried as `owning_namespace`.
    let owning_ns = listener.owning_namespace.as_str();
    let tls = match &listener.tls {
        Some(t) => t,
        None => {
            return ListenerReadiness::InvalidCertificateRef {
                message: "HTTPS listener has no tls configuration".to_string(),
            };
        }
    };

    if tls.passthrough {
        return ListenerReadiness::Invalid {
            message: "tls.mode: Passthrough is not supported; use Terminate".to_string(),
        };
    }

    // Empty/absent hostname means "match any SNI" — stored as the default cert.
    let hostname = listener
        .hostname
        .as_deref()
        .filter(|h| !h.is_empty())
        .unwrap_or("");

    let refs = tls.certificate_refs.as_slice();
    if refs.is_empty() {
        return ListenerReadiness::InvalidCertificateRef {
            message: "tls.certificateRefs is empty".to_string(),
        };
    }

    // Load all certificateRefs (GEP-851). Each ref is validated independently;
    // failures on individual refs do not prevent the others from being loaded.
    // Tracks failures to detect partial success (ResolvedPartial).
    let mut resolved_count: u32 = 0;
    // `(message, is_ref_not_permitted)` for each failed ref.
    let mut failures: Vec<(String, bool)> = Vec::new();

    for cert_ref in refs {
        // Only core/Secret (empty group, "core", or absent) is supported.
        let ref_kind = cert_ref.kind.as_deref().unwrap_or("Secret");
        let ref_group = cert_ref.group.as_deref().unwrap_or("");
        if ref_kind != "Secret" || (!ref_group.is_empty() && ref_group != "core") {
            let msg = format!(
                "unsupported certificateRef {ref_group}/{ref_kind}: only core/Secret is supported"
            );
            failures.push((msg, false));
            continue;
        }

        let ref_ns = cert_ref.namespace.as_deref().unwrap_or(owning_ns);

        if ref_ns != owning_ns
            && !reference_grants::backend_ref_allowed(
                owning_ns,
                ref_ns,
                &cert_ref.name,
                cert_grants,
            )
        {
            tracing::warn!(
                gateway = %format!("{gw_name}"),
                listener = %listener.name,
                secret = %format!("{ref_ns}/{}", cert_ref.name),
                "Cross-namespace certificateRef denied — no matching ReferenceGrant"
            );
            let msg = format!(
                "cross-namespace Secret {ref_ns}/{} requires a ReferenceGrant",
                cert_ref.name
            );
            failures.push((msg, true));
            continue;
        }

        match load_tls_cert(ref_ns, &cert_ref.name, secrets) {
            Ok(cert) => {
                // Count the successful load either way so the readiness verdict is
                // identical whether or not we install; skip the install itself
                // when the bind port is not yet known (VipPending) — see the
                // `install_certs` doc.
                if install_certs {
                    builder.add_cert(bind_port, hostname, Arc::new(cert));
                }
                resolved_count += 1;
                tracing::debug!(
                    gateway = %format!("{gw_name}"),
                    listener = %listener.name,
                    secret = %format!("{ref_ns}/{}", cert_ref.name),
                    hostname,
                    "Gateway TLS cert installed"
                );
            }
            Err(e) => {
                tracing::warn!(
                    gateway = %format!("{gw_name}"),
                    listener = %listener.name,
                    secret = %format!("{ref_ns}/{}", cert_ref.name),
                    error = %e,
                    "Gateway TLS Secret unusable — continuing with remaining refs"
                );
                failures.push((e.to_string(), false));
            }
        }
    }

    if resolved_count == 0 {
        // Every ref failed — surface the most specific failure kind.
        // RefNotPermitted takes priority (operator needs to add a ReferenceGrant)
        // over generic cert errors.
        let any_ref_not_permitted = failures.iter().any(|(_, rnp)| *rnp);
        let messages: Vec<String> = failures.into_iter().map(|(m, _)| m).collect();
        let message = messages.join("; ");
        if any_ref_not_permitted {
            return ListenerReadiness::RefNotPermitted { message };
        }
        return ListenerReadiness::InvalidCertificateRef { message };
    }

    if !failures.is_empty() {
        // Some refs failed but at least one resolved — listener serves the good
        // certs and surfaces the failures via a degraded condition.
        let messages: Vec<String> = failures.into_iter().map(|(m, _)| m).collect();
        let message = format!(
            "{} of {} certificateRef(s) failed: {}",
            messages.len(),
            resolved_count as usize + messages.len(),
            messages.join("; ")
        );
        tracing::warn!(
            gateway = %format!("{gw_name}"),
            listener = %listener.name,
            ?message,
            "Listener is serving only a subset of its certificateRefs (ResolvedPartial)"
        );
        return ListenerReadiness::ResolvedPartial { message };
    }

    ListenerReadiness::Resolved
}
