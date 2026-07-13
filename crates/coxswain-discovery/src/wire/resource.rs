//! Canonical keying and hashing for resource-oriented snapshots (WIRE_VERSION 2).
//!
//! This module is the **single home of the resource key grammar** (#383). Every
//! [`p::Resource`] maps to exactly one canonical key — a `|`-separated string
//! that both halves of the protocol agree on: the server addresses its
//! per-stream acked-resource map by it, and the client keys its resource cache
//! and dirty set by it. Because the grammar lives in one function, the two sides
//! cannot drift.
//!
//! The per-resource content hash ([`resource_hash`]) is `sha256` over the
//! resource's proto bytes; the global snapshot `version` is the order-independent
//! combination of the per-resource hashes (see
//! [`crate::version::ContentHash::from_per_resource`]), so the convergence oracle
//! is formally identical to the v1 whole-table hash.

use sha2::{Digest, Sha256};

use crate::proto::v1 as p;

/// Failure modes of [`canonical_key`].
///
/// A resource that cannot be keyed cannot be placed in the world. This function
/// is the encode/cache-side grammar authority: the server keys its per-stream
/// acked-resource map and the client keys its resource cache + dirty set through
/// it. The decoder (`decode_world`) does not call back here — it validates each
/// incoming resource independently against its own guards and fails an unkeyable
/// snapshot closed (Nack + last-good) on the wire it received.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResourceKeyError {
    /// The `Resource.payload` oneof arm was absent.
    #[error("resource payload oneof is absent")]
    MissingPayload,
    /// A [`p::RouteHostResource`] carried no `host` sub-message.
    #[error("route_host resource is missing its host bucket")]
    MissingHost,
    /// A [`p::RouteHostResource`] host carried no `pattern` oneof arm.
    #[error("route_host resource host carries no pattern")]
    MissingHostPattern,
    /// A [`p::RouteHostResource`] carried an unspecified/unknown `table`.
    #[error("route_host resource carries an unspecified table kind")]
    UnspecifiedTable,
    /// A wildcard host pattern carried an unspecified/unknown [`p::WildcardKind`].
    #[error("route_host wildcard carries an unspecified kind")]
    UnspecifiedWildcardKind,
    /// A canonical-key *string* (a delta tombstone) did not match the grammar:
    /// an unknown prefix, the wrong field count for its variant, or a numeric
    /// field (port) that did not parse. Only `parse_canonical_key` raises this;
    /// [`canonical_key`] cannot, as it emits the grammar rather than parsing it.
    #[error("malformed canonical key string: {reason}")]
    MalformedKey {
        /// Human-readable reason the string failed to parse.
        reason: &'static str,
    },
    /// A [`p::resource::Payload::GatewayMeta`] resource carried no qualifier, or
    /// a resource carried exactly one of `qualifier_namespace`/`qualifier_name`
    /// (#582). Both are required together: a `GatewayMeta` names no Gateway on
    /// its own, and a half-qualified resource cannot be demuxed by a relay.
    #[error("resource qualifier is absent or incomplete")]
    MissingQualifier,
}

/// The parsed form of a canonical key — the inverse of [`canonical_key`].
///
/// A delta's `removed_resources` carries canonical-key *strings*; the client must
/// resolve each back to the typed map it tombstones from. Parsing lives here,
/// beside the emitter, so the grammar has exactly one home and the two directions
/// cannot drift. The variants carry only primitive / owned components (no cache
/// key types) so this module stays free of an `apply` dependency; the caller maps
/// them onto its typed keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParsedKey {
    /// An L7 route host bucket: `(table, port, host)`.
    Route {
        /// `false` = Ingress table, `true` = Gateway table.
        gateway: bool,
        /// Listener (bind) port.
        port: u16,
        /// Host dimension.
        host: ParsedHost,
    },
    /// A per-port terminate TLS store (`tls|<port>`).
    Tls(u16),
    /// A per-port client-certificate config (`clientcert|<port>`).
    ClientCert(u16),
    /// A per-Gateway listener status (`listener|<ns>/<name>`); carries the raw
    /// `ns/name` object-key substring.
    Listener(String),
    /// A TLS-passthrough port (`tlspassthrough|<port>`).
    TlsPassthrough(u16),
    /// A TLS-terminate port (`tlsterminate|<port>`).
    TlsTerminate(u16),
    /// A TCPRoute port (`tcp|<port>`).
    Tcp(u16),
    /// A UDPRoute port (`udp|<port>`).
    Udp(u16),
    /// An EDS endpoint resource (`endpoints|<ns>/<svc>/<port>`).
    Endpoints {
        /// Referenced Service namespace.
        namespace: String,
        /// Referenced Service name.
        service: String,
        /// Referenced Service port.
        port: u16,
    },
    /// A resource qualified to one dedicated Gateway inside a `Namespace` view
    /// (`gw|<ns>|<name>|<inner>`, #582). `inner` is the resource's own
    /// (unqualified) parsed key.
    Qualified {
        /// Owning Gateway's namespace.
        namespace: String,
        /// Owning Gateway's name.
        name: String,
        /// The wrapped resource's own key.
        inner: Box<ParsedKey>,
    },
    /// A per-Gateway publish-seq resource (`gwmeta|<ns>|<name>`, #582).
    GatewayMeta {
        /// Gateway namespace.
        namespace: String,
        /// Gateway name.
        name: String,
    },
}

/// The host dimension of a parsed route key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParsedHost {
    /// An exact hostname.
    Exact(String),
    /// A wildcard host: the bare suffix plus its label-count semantics.
    Wildcard {
        /// Suffix after the wildcard label (no `*.` prefix).
        suffix: String,
        /// `true` = single-label (Ingress), `false` = multi-label (Gateway).
        single_label: bool,
    },
    /// The port's catch-all bucket.
    Catchall,
}

/// The canonical key for `resource`, the single addressing identity used on both
/// the server (acked-resource map) and the client (resource cache + dirty set).
///
/// Grammar (`|`-separated, spellings are load-bearing — the two protocol halves
/// compare these strings byte-for-byte):
/// - `route|<ingress|gateway>|<port>|<exact|wildcard-single|wildcard-multi|catchall>[|<host>]`
/// - `tls|<port>`, `clientcert|<port>`, `tlspassthrough|<port>`,
///   `tlsterminate|<port>`, `tcp|<port>`, `udp|<port>`
/// - `listener|<ns>/<name>`
/// - `endpoints|<ns>/<svc>/<port>`
/// - `gwmeta|<ns>|<name>` (#582, `Namespace`-scope views only)
///
/// For an exact route the host is the hostname; for a wildcard route it is the
/// bare suffix (no `*.` prefix); a catchall route omits the trailing host field.
///
/// Any resource above — except `GatewayMeta`, which is inherently per-Gateway —
/// carries a `gw|<ns>|<name>|` prefix when [`p::Resource::qualifier_namespace`]
/// / `qualifier_name` are set (#582, `Namespace`-scope views): e.g.
/// `gw|prod|gw-a|route|gateway|443|exact|example.com`. `SharedPool`/`Gateway`
/// views never set the qualifier, so their keys and resource bytes are
/// byte-identical to pre-#582 wire output.
///
/// # Errors
///
/// Returns [`ResourceKeyError`] when the resource carries no payload arm, a
/// route-host resource is missing its host / pattern / a concrete table or
/// wildcard kind, or the resource's qualifier is absent/incomplete (a
/// `GatewayMeta` payload with no qualifier, or exactly one of
/// `qualifier_namespace`/`qualifier_name` set).
#[must_use = "the canonical key identifies the resource in the world; discarding it drops the resource"]
pub fn canonical_key(resource: &p::Resource) -> Result<String, ResourceKeyError> {
    // Delimiter-safety invariant: the free-form components spliced into a key
    // below (hostname, wildcard suffix, `ns/name`, `ns/svc/port`) never collide
    // across the `|`/`/` separators because each is either TERMINAL in its key
    // form (nothing follows it, so an embedded separator can't be misparsed) or
    // DNS-1123-constrained (hostnames, namespaces, service names — no `|`, no
    // `/`). Any FUTURE key variant that places a free-form component in an
    // INTERIOR position must escape or reject it, or two distinct resources could
    // map to the same key.
    let payload = resource
        .payload
        .as_ref()
        .ok_or(ResourceKeyError::MissingPayload)?;

    let qualifier = match (
        resource.qualifier_namespace.as_str(),
        resource.qualifier_name.as_str(),
    ) {
        ("", "") => None,
        (ns, name) if !ns.is_empty() && !name.is_empty() => Some((ns, name)),
        _ => return Err(ResourceKeyError::MissingQualifier),
    };

    let key = match payload {
        p::resource::Payload::RouteHost(r) => route_host_key(r)?,
        p::resource::Payload::TlsPort(e) => format!("tls|{}", e.port),
        p::resource::Payload::ClientCertPort(r) => format!("clientcert|{}", r.port),
        p::resource::Payload::ListenerStatus(e) => format!("listener|{}", e.object_key),
        p::resource::Payload::TlsPassthroughPort(pt) => format!("tlspassthrough|{}", pt.port),
        p::resource::Payload::TlsTerminatePort(pt) => format!("tlsterminate|{}", pt.port),
        p::resource::Payload::TcpPort(pt) => format!("tcp|{}", pt.port),
        p::resource::Payload::UdpPort(pt) => format!("udp|{}", pt.port),
        p::resource::Payload::Endpoints(e) => {
            format!("endpoints|{}/{}/{}", e.namespace, e.service, e.port)
        }
        // Inherently per-Gateway: returns directly rather than falling into the
        // shared `gw|<ns>|<name>|` wrapping below (a GatewayMeta's own key IS
        // the qualifier, not a wrapped inner key).
        p::resource::Payload::GatewayMeta(_) => {
            let (ns, name) = qualifier.ok_or(ResourceKeyError::MissingQualifier)?;
            return Ok(format!("gwmeta|{ns}|{name}"));
        }
    };
    Ok(match qualifier {
        Some((ns, name)) => format!("gw|{ns}|{name}|{key}"),
        None => key,
    })
}

/// Canonical key for a [`p::RouteHostResource`]: `route|<table>|<port>|<pattern>[|<host>]`.
fn route_host_key(r: &p::RouteHostResource) -> Result<String, ResourceKeyError> {
    let table = match p::RouteTableKind::try_from(r.table).unwrap_or(p::RouteTableKind::Unspecified)
    {
        p::RouteTableKind::Ingress => "ingress",
        p::RouteTableKind::Gateway => "gateway",
        p::RouteTableKind::Unspecified => return Err(ResourceKeyError::UnspecifiedTable),
    };
    let host = r.host.as_ref().ok_or(ResourceKeyError::MissingHost)?;
    let pattern = host
        .pattern
        .as_ref()
        .ok_or(ResourceKeyError::MissingHostPattern)?;
    let key = match pattern {
        p::host_entry::Pattern::Exact(h) => {
            format!("route|{table}|{}|exact|{h}", r.port)
        }
        p::host_entry::Pattern::Wildcard(w) => {
            let kind =
                match p::WildcardKind::try_from(w.kind).unwrap_or(p::WildcardKind::Unspecified) {
                    p::WildcardKind::SingleLabel => "wildcard-single",
                    p::WildcardKind::MultiLabel => "wildcard-multi",
                    p::WildcardKind::Unspecified => {
                        return Err(ResourceKeyError::UnspecifiedWildcardKind);
                    }
                };
            format!("route|{table}|{}|{kind}|{}", r.port, w.suffix)
        }
        p::host_entry::Pattern::Catchall(_) => {
            format!("route|{table}|{}|catchall", r.port)
        }
    };
    Ok(key)
}

/// Lowercase-hex `sha256` of the resource's proto encoding.
///
/// The per-resource content identity: two resources hash equal iff their proto
/// bytes are equal. Because `to_wire` emits every repeated field in canonical
/// (sorted) order, an unchanged resource re-encodes to identical bytes across
/// reconciles, so its hash is stable and the server can skip re-sending it.
#[must_use = "the resource hash is the per-resource content identity used for change detection"]
pub fn resource_hash(resource: &p::Resource) -> String {
    use prost::Message as _;
    let digest = Sha256::digest(resource.encode_to_vec());
    let mut out = String::with_capacity(digest.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Parse a canonical-key string back into its typed components — the inverse of
/// [`canonical_key`], used to resolve a delta's `removed_resources` tombstones.
///
/// The grammar is `|`-separated with the free-form components (host, `ns/name`,
/// `ns/svc/port`) always terminal, so a left-to-right split by `|` is
/// unambiguous. Numeric ports parse to `u16` (the listener-port range every
/// keyed map keys on).
///
/// # Errors
///
/// Returns [`ResourceKeyError::MalformedKey`] for an unknown prefix, a wrong
/// field count, an out-of-range/non-numeric port, or a wildcard whose kind token
/// is neither `wildcard-single` nor `wildcard-multi`.
#[must_use = "the parsed key identifies which resource a tombstone removes; discarding it drops the removal"]
pub(crate) fn parse_canonical_key(key: &str) -> Result<ParsedKey, ResourceKeyError> {
    let parse_port = parse_canonical_port;

    let (prefix, rest) = match key.split_once('|') {
        Some(split) => split,
        // A bare token with no `|` is only valid if it is itself a whole key,
        // which no variant is — every variant carries at least one field.
        None => {
            return Err(ResourceKeyError::MalformedKey {
                reason: "key carries no '|' separator",
            });
        }
    };

    match prefix {
        "route" => parse_route_key(rest),
        "tls" => Ok(ParsedKey::Tls(parse_port(rest)?)),
        "clientcert" => Ok(ParsedKey::ClientCert(parse_port(rest)?)),
        "tlspassthrough" => Ok(ParsedKey::TlsPassthrough(parse_port(rest)?)),
        "tlsterminate" => Ok(ParsedKey::TlsTerminate(parse_port(rest)?)),
        "tcp" => Ok(ParsedKey::Tcp(parse_port(rest)?)),
        "udp" => Ok(ParsedKey::Udp(parse_port(rest)?)),
        // `listener|<ns>/<name>` — the object-key substring is terminal and
        // DNS-1123-constrained; the caller validates it parses as an `ObjectKey`.
        "listener" => {
            if rest.is_empty() {
                return Err(ResourceKeyError::MalformedKey {
                    reason: "listener key carries no object key",
                });
            }
            Ok(ParsedKey::Listener(rest.to_owned()))
        }
        // `endpoints|<ns>/<svc>/<port>` — split the terminal triple on `/`.
        "endpoints" => {
            let mut parts = rest.splitn(3, '/');
            let namespace = parts.next().unwrap_or_default();
            let service = parts.next();
            let port = parts.next();
            match (service, port) {
                (Some(service), Some(port)) if !namespace.is_empty() && !service.is_empty() => {
                    Ok(ParsedKey::Endpoints {
                        namespace: namespace.to_owned(),
                        service: service.to_owned(),
                        port: parse_port(port)?,
                    })
                }
                _ => Err(ResourceKeyError::MalformedKey {
                    reason: "endpoints key is not ns/svc/port",
                }),
            }
        }
        // `gwmeta|<ns>|<name>` (#582) — the terminal pair is `|`-separated like
        // every other prefix (ns/name are DNS-1123, no embedded `|`).
        "gwmeta" => {
            let mut parts = rest.splitn(2, '|');
            let namespace = parts.next().unwrap_or_default();
            let name = parts.next();
            match name {
                Some(name) if !namespace.is_empty() && !name.is_empty() => {
                    Ok(ParsedKey::GatewayMeta {
                        namespace: namespace.to_owned(),
                        name: name.to_owned(),
                    })
                }
                _ => Err(ResourceKeyError::MalformedKey {
                    reason: "gwmeta key is not ns|name",
                }),
            }
        }
        // `gw|<ns>|<name>|<inner>` (#582) — ns/name are terminal-safe fields,
        // `<inner>` is the wrapped resource's own (unqualified) canonical key
        // and may itself contain further `|` separators, so it is recursed on
        // whole rather than split further here.
        "gw" => {
            let mut parts = rest.splitn(3, '|');
            let namespace = parts.next().unwrap_or_default();
            let name = parts.next();
            let inner = parts.next();
            match (name, inner) {
                (Some(name), Some(inner))
                    if !namespace.is_empty() && !name.is_empty() && !inner.is_empty() =>
                {
                    Ok(ParsedKey::Qualified {
                        namespace: namespace.to_owned(),
                        name: name.to_owned(),
                        inner: Box::new(parse_canonical_key(inner)?),
                    })
                }
                _ => Err(ResourceKeyError::MalformedKey {
                    reason: "gw-qualified key is not ns|name|<inner>",
                }),
            }
        }
        _ => Err(ResourceKeyError::MalformedKey {
            reason: "unknown canonical-key prefix",
        }),
    }
}

/// Parse a port field strictly against its canonical spelling.
///
/// `str::parse::<u16>` alone accepts non-canonical spellings (`"080"`, `"+80"`)
/// that `canonical_key` can never emit. Accepting them would let a tombstone
/// key alias a held resource under a spelling the digest map doesn't use,
/// desyncing digests from the typed maps and bypassing the upsert/remove
/// overlap guard — so the parse round-trips: the input must equal the
/// canonical decimal re-emission.
fn parse_canonical_port(s: &str) -> Result<u16, ResourceKeyError> {
    let port = s
        .parse::<u16>()
        .map_err(|_| ResourceKeyError::MalformedKey {
            reason: "port field is not a u16",
        })?;
    if port.to_string() != s {
        return Err(ResourceKeyError::MalformedKey {
            reason: "port field is not in canonical decimal form",
        });
    }
    Ok(port)
}

/// Parse the tail of a `route|<table>|<port>|<pattern>[|<host>]` key.
fn parse_route_key(rest: &str) -> Result<ParsedKey, ResourceKeyError> {
    // table | port | pattern [ | host ] — the host is terminal, so `splitn(4)`
    // keeps any (DNS-safe, `|`-free) host intact in the final field.
    let mut parts = rest.splitn(4, '|');
    let table = parts.next().unwrap_or_default();
    let gateway = match table {
        "ingress" => false,
        "gateway" => true,
        _ => return Err(ResourceKeyError::UnspecifiedTable),
    };
    let port = parse_canonical_port(parts.next().ok_or(ResourceKeyError::MalformedKey {
        reason: "route key missing its port field",
    })?)?;
    let pattern = parts.next().ok_or(ResourceKeyError::MalformedKey {
        reason: "route key missing its pattern field",
    })?;
    let host = parts.next();
    let host = match (pattern, host) {
        ("exact", Some(h)) if !h.is_empty() => ParsedHost::Exact(h.to_owned()),
        ("wildcard-single", Some(h)) if !h.is_empty() => ParsedHost::Wildcard {
            suffix: h.to_owned(),
            single_label: true,
        },
        ("wildcard-multi", Some(h)) if !h.is_empty() => ParsedHost::Wildcard {
            suffix: h.to_owned(),
            single_label: false,
        },
        ("catchall", None) => ParsedHost::Catchall,
        _ => {
            return Err(ResourceKeyError::MalformedKey {
                reason: "route key host pattern/field mismatch",
            });
        }
    };
    Ok(ParsedKey::Route {
        gateway,
        port,
        host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route_host(
        table: p::RouteTableKind,
        port: u32,
        pattern: p::host_entry::Pattern,
    ) -> p::Resource {
        p::Resource {
            payload: Some(p::resource::Payload::RouteHost(p::RouteHostResource {
                table: table as i32,
                port,
                host: Some(p::HostEntry {
                    pattern: Some(pattern),
                    normalize_level: 0,
                    routes: Vec::new(),
                }),
            })),
            ..Default::default()
        }
    }

    fn wildcard(kind: p::WildcardKind, suffix: &str) -> p::host_entry::Pattern {
        p::host_entry::Pattern::Wildcard(p::WildcardHost {
            suffix: suffix.to_owned(),
            kind: kind as i32,
        })
    }

    /// Canonical-key golden for every resource variant — the exact spellings are
    /// load-bearing: both protocol halves compare these strings byte-for-byte.
    #[test]
    fn canonical_key_goldens() {
        let cases: Vec<(p::Resource, &str)> = vec![
            (
                route_host(
                    p::RouteTableKind::Ingress,
                    80,
                    p::host_entry::Pattern::Exact("example.com".to_owned()),
                ),
                "route|ingress|80|exact|example.com",
            ),
            (
                route_host(
                    p::RouteTableKind::Gateway,
                    443,
                    wildcard(p::WildcardKind::SingleLabel, "example.com"),
                ),
                "route|gateway|443|wildcard-single|example.com",
            ),
            (
                route_host(
                    p::RouteTableKind::Gateway,
                    443,
                    wildcard(p::WildcardKind::MultiLabel, "example.com"),
                ),
                "route|gateway|443|wildcard-multi|example.com",
            ),
            (
                route_host(
                    p::RouteTableKind::Ingress,
                    80,
                    p::host_entry::Pattern::Catchall(true),
                ),
                "route|ingress|80|catchall",
            ),
            (
                p::Resource {
                    payload: Some(p::resource::Payload::TlsPort(p::PortTlsEntry {
                        port: 443,
                        store: None,
                    })),
                    ..Default::default()
                },
                "tls|443",
            ),
            (
                p::Resource {
                    payload: Some(p::resource::Payload::ClientCertPort(
                        p::ClientCertPortResource {
                            port: 443,
                            entries: Vec::new(),
                        },
                    )),
                    ..Default::default()
                },
                "clientcert|443",
            ),
            (
                p::Resource {
                    payload: Some(p::resource::Payload::ListenerStatus(
                        p::GatewayStatusEntry {
                            object_key: "prod/gw-a".to_owned(),
                            status: None,
                        },
                    )),
                    ..Default::default()
                },
                "listener|prod/gw-a",
            ),
            (
                p::Resource {
                    payload: Some(p::resource::Payload::TlsPassthroughPort(
                        p::TlsPassthroughPort {
                            port: 8443,
                            entries: Vec::new(),
                        },
                    )),
                    ..Default::default()
                },
                "tlspassthrough|8443",
            ),
            (
                p::Resource {
                    payload: Some(p::resource::Payload::TlsTerminatePort(
                        p::TlsPassthroughPort {
                            port: 8443,
                            entries: Vec::new(),
                        },
                    )),
                    ..Default::default()
                },
                "tlsterminate|8443",
            ),
            (
                p::Resource {
                    payload: Some(p::resource::Payload::TcpPort(p::TcpRoutePort {
                        port: 9000,
                        backend_group: None,
                    })),
                    ..Default::default()
                },
                "tcp|9000",
            ),
            (
                p::Resource {
                    payload: Some(p::resource::Payload::UdpPort(p::UdpRoutePort {
                        port: 5353,
                        backend_group: None,
                    })),
                    ..Default::default()
                },
                "udp|5353",
            ),
            (
                p::Resource {
                    payload: Some(p::resource::Payload::Endpoints(p::EndpointResource {
                        namespace: "default".to_owned(),
                        service: "svc".to_owned(),
                        port: 80,
                        app_protocol: 0,
                        service_exists: true,
                        addrs: Vec::new(),
                    })),
                    ..Default::default()
                },
                "endpoints|default/svc/80",
            ),
        ];
        for (resource, expected) in cases {
            assert_eq!(
                canonical_key(&resource).expect("keyable"),
                expected,
                "canonical key mismatch"
            );
        }
    }

    /// `parse_canonical_key` is the inverse of `canonical_key` for every variant:
    /// the golden strings parse back into the typed components they encode.
    #[test]
    fn parse_canonical_key_round_trips_goldens() {
        let cases: Vec<(&str, ParsedKey)> = vec![
            (
                "route|ingress|80|exact|example.com",
                ParsedKey::Route {
                    gateway: false,
                    port: 80,
                    host: ParsedHost::Exact("example.com".to_owned()),
                },
            ),
            (
                "route|gateway|443|wildcard-single|example.com",
                ParsedKey::Route {
                    gateway: true,
                    port: 443,
                    host: ParsedHost::Wildcard {
                        suffix: "example.com".to_owned(),
                        single_label: true,
                    },
                },
            ),
            (
                "route|gateway|443|wildcard-multi|example.com",
                ParsedKey::Route {
                    gateway: true,
                    port: 443,
                    host: ParsedHost::Wildcard {
                        suffix: "example.com".to_owned(),
                        single_label: false,
                    },
                },
            ),
            (
                "route|ingress|80|catchall",
                ParsedKey::Route {
                    gateway: false,
                    port: 80,
                    host: ParsedHost::Catchall,
                },
            ),
            ("tls|443", ParsedKey::Tls(443)),
            ("clientcert|443", ParsedKey::ClientCert(443)),
            (
                "listener|prod/gw-a",
                ParsedKey::Listener("prod/gw-a".to_owned()),
            ),
            ("tlspassthrough|8443", ParsedKey::TlsPassthrough(8443)),
            ("tlsterminate|8443", ParsedKey::TlsTerminate(8443)),
            ("tcp|9000", ParsedKey::Tcp(9000)),
            ("udp|5353", ParsedKey::Udp(5353)),
            (
                "endpoints|default/svc/80",
                ParsedKey::Endpoints {
                    namespace: "default".to_owned(),
                    service: "svc".to_owned(),
                    port: 80,
                },
            ),
        ];
        for (key, expected) in cases {
            assert_eq!(
                parse_canonical_key(key).expect("parseable"),
                expected,
                "{key}"
            );
        }
    }

    /// Malformed tombstone key strings are rejected, not silently mis-parsed.
    #[test]
    fn parse_canonical_key_rejects_malformed() {
        for bad in [
            "bogus|80",                          // unknown prefix
            "tls",                               // no separator
            "tls|notaport",                      // non-numeric port
            "tls|70000",                         // port out of u16 range
            "tls|080",                           // non-canonical port (leading zero)
            "tls|+80",                           // non-canonical port (leading plus)
            "route|elsewhere|80|catchall",       // unknown table
            "route|ingress|80",                  // missing pattern
            "route|ingress|80|exact",            // exact without a host
            "route|ingress|80|exact|",           // exact with an empty host
            "route|ingress|80|wildcard-single|", // wildcard with an empty suffix
            "route|ingress|80|wildcard-bogus|h", // unknown wildcard-kind token
            "route|ingress|80|catchall|extra",   // catchall with a stray host
            "endpoints|ns/svc",                  // endpoints missing the port
            "endpoints|/svc/80",                 // endpoints with an empty namespace
            "endpoints|ns//80",                  // endpoints with an empty service
            "listener|",                         // listener without an object key
        ] {
            assert!(
                parse_canonical_key(bad).is_err(),
                "expected malformed key to be rejected: {bad}"
            );
        }
    }

    /// A resource with no payload arm (an unknown future variant, decoded to None)
    /// cannot be keyed.
    #[test]
    fn missing_payload_is_unkeyable() {
        let err = canonical_key(&p::Resource {
            payload: None,
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err, ResourceKeyError::MissingPayload);
    }

    /// Oneof-tag sensitivity: the SAME payload under the passthrough vs terminate
    /// arm encodes with a different field tag, so the resource hashes differ —
    /// the two tables never collide even at identical ports.
    #[test]
    fn oneof_tag_changes_hash() {
        let port = p::TlsPassthroughPort {
            port: 8443,
            entries: Vec::new(),
        };
        let passthrough = p::Resource {
            payload: Some(p::resource::Payload::TlsPassthroughPort(port.clone())),
            ..Default::default()
        };
        let terminate = p::Resource {
            payload: Some(p::resource::Payload::TlsTerminatePort(port)),
            ..Default::default()
        };
        assert_ne!(
            resource_hash(&passthrough),
            resource_hash(&terminate),
            "identical payload under a different oneof tag must hash differently"
        );
        assert_ne!(
            canonical_key(&passthrough).unwrap(),
            canonical_key(&terminate).unwrap(),
        );
    }

    /// Identical resources hash identically (change-detection stability).
    #[test]
    fn resource_hash_is_stable() {
        let a = route_host(
            p::RouteTableKind::Ingress,
            80,
            p::host_entry::Pattern::Exact("example.com".to_owned()),
        );
        let b = route_host(
            p::RouteTableKind::Ingress,
            80,
            p::host_entry::Pattern::Exact("example.com".to_owned()),
        );
        assert_eq!(resource_hash(&a), resource_hash(&b));
    }

    // ── #582: per-Gateway qualifier + GatewayMeta ───────────────────────────

    fn qualified(resource: p::Resource, namespace: &str, name: &str) -> p::Resource {
        p::Resource {
            qualifier_namespace: namespace.to_owned(),
            qualifier_name: name.to_owned(),
            ..resource
        }
    }

    fn gateway_meta(namespace: &str, name: &str, publish_seq: u64) -> p::Resource {
        p::Resource {
            payload: Some(p::resource::Payload::GatewayMeta(p::GatewayMeta {
                publish_seq,
            })),
            qualifier_namespace: namespace.to_owned(),
            qualifier_name: name.to_owned(),
        }
    }

    /// A qualified resource's canonical key is `gw|<ns>|<name>|` prepended to
    /// its own unqualified key.
    #[test]
    fn qualified_resource_key_golden() {
        let base = route_host(
            p::RouteTableKind::Gateway,
            443,
            p::host_entry::Pattern::Exact("example.com".to_owned()),
        );
        let resource = qualified(base, "prod", "gw-a");
        assert_eq!(
            canonical_key(&resource).expect("keyable"),
            "gw|prod|gw-a|route|gateway|443|exact|example.com"
        );
    }

    /// A `GatewayMeta` resource keys to `gwmeta|<ns>|<name>` — its own key IS
    /// the qualifier, not a wrapped inner key.
    #[test]
    fn gateway_meta_key_golden() {
        let resource = gateway_meta("prod", "gw-a", 7);
        assert_eq!(
            canonical_key(&resource).expect("keyable"),
            "gwmeta|prod|gw-a"
        );
    }

    /// `parse_canonical_key` round-trips both new #582 key shapes.
    #[test]
    fn parse_canonical_key_round_trips_582_goldens() {
        assert_eq!(
            parse_canonical_key("gw|prod|gw-a|route|gateway|443|exact|example.com")
                .expect("parseable"),
            ParsedKey::Qualified {
                namespace: "prod".to_owned(),
                name: "gw-a".to_owned(),
                inner: Box::new(ParsedKey::Route {
                    gateway: true,
                    port: 443,
                    host: ParsedHost::Exact("example.com".to_owned()),
                }),
            }
        );
        assert_eq!(
            parse_canonical_key("gwmeta|prod|gw-a").expect("parseable"),
            ParsedKey::GatewayMeta {
                namespace: "prod".to_owned(),
                name: "gw-a".to_owned(),
            }
        );
    }

    /// A `GatewayMeta` payload with no qualifier cannot be keyed — it would
    /// name no Gateway.
    #[test]
    fn gateway_meta_without_qualifier_is_unkeyable() {
        let resource = p::Resource {
            payload: Some(p::resource::Payload::GatewayMeta(p::GatewayMeta {
                publish_seq: 1,
            })),
            ..Default::default()
        };
        assert_eq!(
            canonical_key(&resource).unwrap_err(),
            ResourceKeyError::MissingQualifier
        );
    }

    /// A resource carrying exactly one of `qualifier_namespace`/`qualifier_name`
    /// is half-qualified and cannot be demuxed to a Gateway.
    #[test]
    fn half_qualified_resource_is_unkeyable() {
        let half = p::Resource {
            qualifier_namespace: "prod".to_owned(),
            ..route_host(
                p::RouteTableKind::Gateway,
                443,
                p::host_entry::Pattern::Exact("example.com".to_owned()),
            )
        };
        assert_eq!(
            canonical_key(&half).unwrap_err(),
            ResourceKeyError::MissingQualifier
        );
    }

    /// Regression guard for the #582 "byte-identical" acceptance criterion: a
    /// resource with an empty qualifier (every `SharedPool`/`Gateway` resource)
    /// keys and hashes exactly as it did before the qualifier fields existed.
    #[test]
    fn unqualified_resource_is_byte_identical_to_pre_582() {
        let resource = route_host(
            p::RouteTableKind::Ingress,
            80,
            p::host_entry::Pattern::Exact("example.com".to_owned()),
        );
        assert_eq!(
            canonical_key(&resource).expect("keyable"),
            "route|ingress|80|exact|example.com",
            "empty qualifier must not alter the canonical key"
        );

        // A minimal resource (one scalar field, no nested message) whose encoded
        // bytes are hand-computable: `Resource.tls_port = 12` (tag 0x62), a
        // 3-byte embedded `PortTlsEntry { port: 443 }` (field 1, varint tag
        // 0x08, value 443 = varint [0xBB, 0x03]), `store` omitted (None). If
        // the #582 qualifier fields (tags 30/31) encoded even as empty proto3
        // strings, this golden byte vector would grow — it does not.
        use prost::Message as _;
        let minimal = p::Resource {
            payload: Some(p::resource::Payload::TlsPort(p::PortTlsEntry {
                port: 443,
                store: None,
            })),
            ..Default::default()
        };
        assert_eq!(
            minimal.encode_to_vec(),
            vec![0x62, 0x03, 0x08, 0xBB, 0x03],
            "an empty #582 qualifier must not add a single byte to the wire encoding"
        );
    }

    /// Two Gateways with byte-identical resource content hash distinctly once
    /// qualified — the qualifier fields are part of the hashed proto bytes.
    #[test]
    fn same_content_different_qualifier_hashes_distinctly() {
        let base = || {
            route_host(
                p::RouteTableKind::Gateway,
                443,
                p::host_entry::Pattern::Exact("example.com".to_owned()),
            )
        };
        let gw_a = qualified(base(), "prod", "gw-a");
        let gw_b = qualified(base(), "prod", "gw-b");
        assert_ne!(resource_hash(&gw_a), resource_hash(&gw_b));
        assert_ne!(canonical_key(&gw_a).unwrap(), canonical_key(&gw_b).unwrap());
    }
}
