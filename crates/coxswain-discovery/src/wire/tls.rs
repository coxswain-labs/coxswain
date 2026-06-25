//! Wire-DTO conversions between compiled routing types and proto3 messages.
//!
//! # Overview
//!
//! The controller calls `to_wire` to serialise a compiled [`RoutingTable`] into
//! a proto message and then embeds it in a [`Snapshot`].  The proxy
//! calls `from_wire` on arrival and replays the builder API — exactly the same
//! public constructors the reflector uses — to produce a freshly-compiled table
//! without ever touching the Kubernetes API.
//!
//! # Determinism
//!
//! All `to_wire` functions emit data in deterministic canonical order:
//! - Ports: ascending by port number.
//! - Hosts per port: exact entries first (sorted by hostname), then wildcard
//!   (sorted by suffix), then catchall.
//! - Routes per host: in `wire_entries()` insertion order — the order the
//!   reflector registered them, which is stable across reconcile cycles for the
//!   same set of Ingress/HTTPRoute objects.
//! - Addresses inside a backend: sorted for hash stability.
//! - CIDRs: sorted string representation.
//! - TLS/mTLS entries: sorted by host pattern.
//! - Listener health entries: sorted by `ObjectKey` string.
//!
//! No `map<>` fields appear anywhere in the proto; all maps are `repeated Entry`
//! emitted in sorted order.  This makes the serialised bytes byte-identical
//! across reconcile cycles for the same routing world, which keeps the
//! `ContentHash` oracle stable.
//!
//! Per-pattern cert vecs are already sorted by [`TlsStoreBuilder::build`]
//! (ECDSA → RSA → Other, newest `notAfter` first), so the wire order is
//! canonical without extra sorting here.
//!
//! # Recursion guard
//!
//! `FilterAction::Mirror` embeds an `Arc<BackendGroup>`, which itself may carry
//! `per_backend_filters` containing further `Mirror` actions.  In practice the
//! graph is a tree (no cycles), but the proto is untrusted: `from_wire` limits
//! recursion through Mirror backends to [`MAX_MIRROR_DEPTH`].
//!
//! [`RoutingTable`]: coxswain_core::routing::RoutingTable
//! [`Snapshot`]: crate::proto::v1::Snapshot

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use coxswain_core::tls::{
    ClientCertConfig, ClientCertConfigState, ClientCertStore, ClientCertStoreBuilder, KeyAlgorithm,
    TlsCert, TlsStore, TlsStoreBuilder,
};

use crate::error::WireError;
use crate::proto::v1 as p;

// ────────────────────────────────────────────────────────────────────────────
// TLS store: to_wire
// ────────────────────────────────────────────────────────────────────────────

/// Serialise a [`TlsStore`] to its wire DTO.
#[must_use = "wire DTO must be embedded in a Snapshot to reach the proxy"]
pub fn tls_to_wire(store: &TlsStore) -> p::TlsStore {
    let mut exact_entries: Vec<(&str, &[Arc<TlsCert>])> = store.iter_exact_all().collect();
    exact_entries.sort_by_key(|(h, _)| *h);

    let mut wildcard_entries: Vec<(&str, &[Arc<TlsCert>])> = store.iter_wildcard_all().collect();
    wildcard_entries.sort_by_key(|(s, _)| *s);

    p::TlsStore {
        exact: exact_entries
            .into_iter()
            .map(|(h, certs)| p::TlsCertEntry {
                host_pattern: h.to_string(),
                certs: certs.iter().map(|c| tls_cert_to_wire(c)).collect(),
            })
            .collect(),
        wildcard: wildcard_entries
            .into_iter()
            .map(|(s, certs)| p::TlsCertEntry {
                host_pattern: s.to_string(),
                certs: certs.iter().map(|c| tls_cert_to_wire(c)).collect(),
            })
            .collect(),
        default_certs: store
            .default_certs()
            .iter()
            .map(|c| tls_cert_to_wire(c))
            .collect(),
    }
}

fn tls_cert_to_wire(c: &TlsCert) -> p::TlsCert {
    p::TlsCert {
        cert_pem: c.cert_pem.clone(),
        key_pem: c.key_pem.clone(),
        source: c.source.clone(),
        not_after_unix_secs: c
            .not_after
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())),
        key_algorithm: key_algorithm_to_wire(c.key_algorithm) as i32,
    }
}

fn key_algorithm_to_wire(algo: KeyAlgorithm) -> p::KeyAlgorithm {
    match algo {
        KeyAlgorithm::Rsa => p::KeyAlgorithm::Rsa,
        KeyAlgorithm::Ecdsa => p::KeyAlgorithm::Ecdsa,
        KeyAlgorithm::Other => p::KeyAlgorithm::Other,
        _ => p::KeyAlgorithm::Unspecified,
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Client-cert store: to_wire
// ────────────────────────────────────────────────────────────────────────────

/// Serialise a [`ClientCertStore`] to its wire DTO.
#[must_use = "wire DTO must be embedded in a Snapshot to reach the proxy"]
pub fn client_cert_to_wire(store: &ClientCertStore) -> p::ClientCertStore {
    let mut exact_entries: Vec<(&str, Arc<ClientCertConfigState>)> = store
        .iter_exact()
        .map(|(h, s)| (h, Arc::clone(s)))
        .collect();
    exact_entries.sort_by_key(|(h, _)| *h);

    let mut wildcard_entries: Vec<(&str, Arc<ClientCertConfigState>)> = store
        .iter_wildcard()
        .map(|(s, cfg)| (s, Arc::clone(cfg)))
        .collect();
    wildcard_entries.sort_by_key(|(s, _)| *s);

    p::ClientCertStore {
        exact: exact_entries
            .into_iter()
            .map(|(h, s)| p::ClientCertEntry {
                host_pattern: h.to_string(),
                state: Some(client_cert_state_to_wire(&s)),
            })
            .collect(),
        wildcard: wildcard_entries
            .into_iter()
            .map(|(s, cfg)| p::ClientCertEntry {
                host_pattern: s.to_string(),
                state: Some(client_cert_state_to_wire(&cfg)),
            })
            .collect(),
        default: store.default_state().map(|s| client_cert_state_to_wire(s)),
    }
}

fn client_cert_state_to_wire(s: &ClientCertConfigState) -> p::ClientCertConfigState {
    let kind = match s {
        ClientCertConfigState::Config(cfg) => {
            p::client_cert_config_state::Kind::Config(p::ClientCertConfig {
                ca_pem: cfg.ca_pem.clone(),
                verify_depth: cfg.verify_depth,
                pass_to_upstream: cfg.pass_to_upstream,
            })
        }
        ClientCertConfigState::Unavailable => p::client_cert_config_state::Kind::Unavailable(true),
        &_ => unreachable!(
            "invariant: all ClientCertConfigState variants handled; \
             add a new arm when the core type gains a variant"
        ),
    };
    p::ClientCertConfigState { kind: Some(kind) }
}

// ────────────────────────────────────────────────────────────────────────────
// TLS store: from_wire
// ────────────────────────────────────────────────────────────────────────────

/// Reconstruct a [`TlsStore`] from its wire DTO.
///
/// # Errors
///
/// Returns [`WireError`] if any required field is missing.
#[must_use = "the rebuilt TLS store must be stored for the proxy to use it"]
pub fn tls_from_wire(dto: &p::TlsStore) -> Result<TlsStore, WireError> {
    let mut builder = TlsStoreBuilder::new();
    for entry in &dto.exact {
        for cert_dto in &entry.certs {
            builder.add_cert(&entry.host_pattern, Arc::new(cert_from_wire(cert_dto)));
        }
    }
    for entry in &dto.wildcard {
        // Wildcard entries store the suffix; add_cert expects "*.{suffix}".
        let pattern = format!("*.{}", entry.host_pattern);
        for cert_dto in &entry.certs {
            builder.add_cert(&pattern, Arc::new(cert_from_wire(cert_dto)));
        }
    }
    for cert_dto in &dto.default_certs {
        // Empty pattern → default bucket in add_cert.
        builder.add_cert("", Arc::new(cert_from_wire(cert_dto)));
    }
    Ok(builder.build())
}

fn cert_from_wire(dto: &p::TlsCert) -> TlsCert {
    let not_after = dto
        .not_after_unix_secs
        .map(|s| UNIX_EPOCH + Duration::from_secs(s));
    let key_algorithm = match p::KeyAlgorithm::try_from(dto.key_algorithm)
        .unwrap_or(p::KeyAlgorithm::Unspecified)
    {
        p::KeyAlgorithm::Rsa => KeyAlgorithm::Rsa,
        p::KeyAlgorithm::Ecdsa => KeyAlgorithm::Ecdsa,
        p::KeyAlgorithm::Other | p::KeyAlgorithm::Unspecified => KeyAlgorithm::Other,
    };
    TlsCert::new(
        dto.cert_pem.clone(),
        dto.key_pem.clone(),
        dto.source.clone(),
    )
    .with_not_after(not_after)
    .with_key_algorithm(key_algorithm)
}

// ────────────────────────────────────────────────────────────────────────────
// Client-cert store: from_wire
// ────────────────────────────────────────────────────────────────────────────

/// Reconstruct a [`ClientCertStore`] from its wire DTO.
///
/// # Errors
///
/// Returns [`WireError`] if any required field is missing.
#[must_use = "the rebuilt client-cert store must be stored for the proxy to use it"]
pub fn client_cert_from_wire(dto: &p::ClientCertStore) -> Result<ClientCertStore, WireError> {
    let mut builder = ClientCertStoreBuilder::new();
    for entry in &dto.exact {
        let state = client_cert_state_from_wire(entry.state.as_ref().ok_or(
            WireError::MissingRequiredField {
                field: "client_cert_entry.state",
            },
        )?);
        builder.add_config(&entry.host_pattern, Arc::new(state));
    }
    for entry in &dto.wildcard {
        let state = client_cert_state_from_wire(entry.state.as_ref().ok_or(
            WireError::MissingRequiredField {
                field: "client_cert_entry.state",
            },
        )?);
        let pattern = format!("*.{}", entry.host_pattern);
        builder.add_config(&pattern, Arc::new(state));
    }
    if let Some(default_dto) = &dto.default {
        let state = client_cert_state_from_wire(default_dto);
        builder.add_config("", Arc::new(state));
    }
    Ok(builder.build())
}

fn client_cert_state_from_wire(dto: &p::ClientCertConfigState) -> ClientCertConfigState {
    match &dto.kind {
        Some(p::client_cert_config_state::Kind::Config(cfg)) => ClientCertConfigState::Config(
            ClientCertConfig::new(cfg.ca_pem.clone(), cfg.verify_depth, cfg.pass_to_upstream),
        ),
        Some(p::client_cert_config_state::Kind::Unavailable(_)) | None => {
            ClientCertConfigState::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── 5. TLS store exact + wildcard + default ───────────────────────────────

    #[test]
    fn tls_store_round_trips() {
        fn cert(source: &str) -> Arc<TlsCert> {
            Arc::new(TlsCert::new(
                b"CERT".to_vec(),
                b"KEY".to_vec(),
                source.to_string(),
            ))
        }

        let mut b = TlsStoreBuilder::new();
        b.add_cert("exact.example.com", cert("exact"));
        b.add_cert("*.example.com", cert("wildcard"));
        b.add_cert("*", cert("default")); // "*" maps to the default fallback slot
        let store = b.build();

        let dto = tls_to_wire(&store);
        let store2 = tls_from_wire(&dto).expect("from_wire");

        assert!(store2.find_cert("exact.example.com").is_some(), "exact hit");
        assert!(
            store2.find_cert("sub.example.com").is_some(),
            "wildcard hit"
        );
        assert!(
            store2.find_cert("other.io").is_some(),
            "default fallback hit"
        );
    }

    #[test]
    fn tls_store_multi_cert_round_trips() {
        fn cert_algo(source: &str, algo: KeyAlgorithm) -> Arc<TlsCert> {
            Arc::new(
                TlsCert::new(
                    format!("CERT-{source}").into_bytes(),
                    b"KEY".to_vec(),
                    source.to_string(),
                )
                .with_key_algorithm(algo),
            )
        }

        let mut b = TlsStoreBuilder::new();
        b.add_cert("example.com", cert_algo("ecdsa", KeyAlgorithm::Ecdsa));
        b.add_cert("example.com", cert_algo("rsa", KeyAlgorithm::Rsa));
        let store = b.build();

        // Both certs survive round-trip.
        let dto = tls_to_wire(&store);
        let store2 = tls_from_wire(&dto).expect("from_wire");
        let certs = store2.find_certs("example.com");
        assert_eq!(certs.len(), 2, "both certs survive round-trip");
        assert_eq!(
            certs[0].key_algorithm,
            KeyAlgorithm::Ecdsa,
            "ECDSA first after round-trip"
        );
        assert_eq!(
            certs[1].key_algorithm,
            KeyAlgorithm::Rsa,
            "RSA second after round-trip"
        );
    }

    #[test]
    fn key_algorithm_round_trips() {
        for algo in [KeyAlgorithm::Rsa, KeyAlgorithm::Ecdsa, KeyAlgorithm::Other] {
            let c = Arc::new(
                TlsCert::new(b"CERT".to_vec(), b"KEY".to_vec(), "src".to_string())
                    .with_key_algorithm(algo),
            );
            let mut b = TlsStoreBuilder::new();
            b.add_cert("host.example.com", c);
            let dto = tls_to_wire(&b.build());
            let store2 = tls_from_wire(&dto).expect("from_wire");
            let certs = store2.find_certs("host.example.com");
            assert_eq!(
                certs[0].key_algorithm, algo,
                "algorithm round-trip for {algo:?}"
            );
        }
    }

    // ── 6. mTLS Config + Unavailable ─────────────────────────────────────────

    #[test]
    fn client_cert_store_config_and_unavailable_round_trip() {
        let cfg = Arc::new(ClientCertConfigState::Config(ClientCertConfig::new(
            b"CA".to_vec(),
            3,
            true,
        )));
        let unavail = Arc::new(ClientCertConfigState::Unavailable);

        let mut b = ClientCertStoreBuilder::new();
        b.add_config("strict.example.com", cfg);
        b.add_config("*.example.com", unavail);
        let store = b.build();

        let dto = client_cert_to_wire(&store);
        let store2 = client_cert_from_wire(&dto).expect("from_wire");

        match store2.find_config("strict.example.com").as_deref() {
            Some(ClientCertConfigState::Config(c)) => {
                assert_eq!(c.verify_depth, 3, "verify_depth preserved");
                assert!(c.pass_to_upstream, "pass_to_upstream preserved");
            }
            other => panic!("expected Config, got {other:?}"),
        }
        match store2.find_config("sub.example.com").as_deref() {
            Some(ClientCertConfigState::Unavailable) => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }
}
