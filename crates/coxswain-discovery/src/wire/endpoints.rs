//! EDS-style endpoint resource decoding (WIRE_VERSION 2).
//!
//! The wire carries endpoints as separately-addressed [`p::EndpointResource`]s
//! keyed by `(namespace, service, port)`; each [`p::WeightedBackend`] references
//! one by [`p::EndpointRef`] instead of inlining pod addresses (#383). This
//! module parses those resources into the shared [`EndpointPool`] the routing
//! decoders resolve refs against, and parses one endpoint resource into its
//! [`ResolvedEndpoints`] value.
//!
//! Referential integrity is a protocol invariant: the server ships every
//! referenced endpoint resource in the same message, so a `bg_from_wire` ref
//! miss is a hard [`WireError::UnknownEndpointRef`] (Nack + last-good), never a
//! fabricated empty group.

use std::net::SocketAddr;
#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use coxswain_core::endpoints::EndpointPool;
use coxswain_core::endpoints::{EndpointKey, ResolvedEndpoints};

use crate::error::WireError;
use crate::proto::v1 as p;
use crate::wire::routing::protocol_from_wire;

/// Build the [`EndpointKey`] `(namespace, service, port)` from wire scalars.
///
/// The `u32` port narrows to `u16`: the sole producer writes `u32::from(u16)`, so
/// the value is in range by construction. Out-of-range ports are **not** the
/// concern of this helper — they are rejected upstream before a key is built: the
/// apply path narrows endpoint-resource ports with a typed error at stage, and
/// `bg_from_wire` narrows a `WeightedBackend.endpoint_ref` port with
/// [`WireError::UnknownEndpointRef`] before calling here. Both guarantee `port`
/// already fits `u16`, so a caller passing an out-of-range value is a bug, not
/// untrusted input (a bare narrow here would truncate `65616 → 80` and bind an
/// unrelated port's endpoints).
#[must_use]
pub(crate) fn endpoint_key_from_wire(namespace: &str, service: &str, port: u32) -> EndpointKey {
    EndpointKey::new(namespace, service, port as u16)
}

/// Parse one [`p::EndpointResource`] into its [`ResolvedEndpoints`] value.
///
/// # Errors
///
/// Returns [`WireError::InvalidAddr`] if any `addrs` entry is not a valid
/// `ip:port` socket address.
#[must_use = "the resolved endpoints must be inserted into the pool for routes to reference"]
pub(crate) fn resolved_endpoints_from_wire(
    e: &p::EndpointResource,
) -> Result<ResolvedEndpoints, WireError> {
    let addrs: Vec<SocketAddr> = e
        .addrs
        .iter()
        .map(|s| s.parse::<SocketAddr>().map_err(WireError::InvalidAddr))
        .collect::<Result<_, _>>()?;
    let app_protocol = protocol_from_wire(e.app_protocol)?;
    Ok(ResolvedEndpoints::new(
        addrs,
        app_protocol,
        e.service_exists,
    ))
}

/// Collect every [`p::EndpointResource`] in `resources` into an [`EndpointPool`].
///
/// Later duplicates for the same key overwrite earlier ones — the server never
/// emits duplicate endpoint keys (one resource per key), so this is a defensive
/// last-wins rather than a meaningful policy.
///
/// # Errors
///
/// Returns the first [`WireError`] from parsing an endpoint resource's addresses.
///
/// Test-only: the production apply path (`apply::apply_message`) builds its pool
/// from the *staged* endpoint world (committed ∪ delta upserts − tombstones), not
/// from a single message — the whole-message form now backs only `decode_world`
/// and unit tests.
#[cfg(test)]
#[must_use = "the endpoint pool must be threaded into the routing decoders to resolve refs"]
pub(crate) fn endpoint_pool_from_resources(
    resources: &[p::Resource],
) -> Result<EndpointPool, WireError> {
    let mut pool = EndpointPool::new();
    for resource in resources {
        if let Some(p::resource::Payload::Endpoints(e)) = &resource.payload {
            let key = endpoint_key_from_wire(&e.namespace, &e.service, e.port);
            pool.insert(key, Arc::new(resolved_endpoints_from_wire(e)?));
        }
    }
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scaled-to-zero Service travels as a zero-addr EndpointResource with
    /// `service_exists = true` — the meaningful-503 signal that must survive the
    /// pool round-trip (invariant 3).
    #[test]
    fn zero_addr_service_exists_round_trips() {
        let resource = p::Resource {
            payload: Some(p::resource::Payload::Endpoints(p::EndpointResource {
                namespace: "default".to_owned(),
                service: "svc".to_owned(),
                port: 80,
                app_protocol: 0,
                service_exists: true,
                addrs: Vec::new(),
            })),
        };
        let pool = endpoint_pool_from_resources(std::slice::from_ref(&resource)).expect("pool");
        let key = endpoint_key_from_wire("default", "svc", 80);
        let ep = pool.get(&key).expect("endpoint present");
        assert!(ep.addrs.is_empty(), "zero addrs preserved");
        assert!(ep.service_exists, "service_exists preserved (drives 503)");
    }

    /// A resource whose addrs parse validly round-trips into resolved endpoints.
    #[test]
    fn endpoints_with_addrs_round_trip() {
        let e = p::EndpointResource {
            namespace: "ns".to_owned(),
            service: "svc".to_owned(),
            port: 8080,
            app_protocol: 0,
            service_exists: true,
            addrs: vec!["10.0.0.1:80".to_owned(), "10.0.0.2:80".to_owned()],
        };
        let resolved = resolved_endpoints_from_wire(&e).expect("resolved");
        assert_eq!(resolved.addrs.len(), 2);
        assert!(resolved.service_exists);
    }

    /// A malformed address fails the decode (Nack path).
    #[test]
    fn bad_addr_errors() {
        let e = p::EndpointResource {
            namespace: "ns".to_owned(),
            service: "svc".to_owned(),
            port: 80,
            app_protocol: 0,
            service_exists: true,
            addrs: vec!["not-an-addr".to_owned()],
        };
        assert!(matches!(
            resolved_endpoints_from_wire(&e),
            Err(WireError::InvalidAddr(_))
        ));
    }
}
