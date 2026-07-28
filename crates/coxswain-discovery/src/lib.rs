//! `coxswain-discovery` — the gRPC discovery control plane.
//!
//! This crate owns the bidirectional gRPC stream between the controller (server)
//! and proxy nodes (clients). The controller compiles K8s-derived routing
//! snapshots into a wire DTO and pushes them over the stream; proxies apply the
//! snapshot to their in-process [`Shared`] routing table without ever touching
//! the Kubernetes API.
//!
//! Two tonic listeners are wired by `coxswain-bin`:
//!
//! - **Stream listener** (port 50051, mTLS mandatory): [`DiscoveryService`] +
//!   [`DiscoveryServerTls`].  Proxy must present a valid SVID.
//! - **Bootstrap listener** (port 50052, server-auth-only TLS):
//!   [`BootstrapService`] + [`DiscoveryBootstrapServerTls`].  Proxy presents
//!   a ServiceAccount token + CSR; the controller signs a short-lived SVID.
//!
//! The crate depends only on [`coxswain_core`] (epic design decision #9 in
//! #238: `coxswain-admin` and `coxswain-discovery` communicate through
//! `coxswain-core` `Shared` handles wired by `coxswain-bin`).
//!
//! [`Shared`]: coxswain_core::Shared

pub(crate) mod apply;
pub(crate) mod auth;
pub(crate) mod bootstrap_client;
pub(crate) mod bootstrap_server;
pub(crate) mod client;
pub(crate) mod error;
pub(crate) mod materialize;
pub(crate) mod metrics;
// `proto` and `wire` stay public: they are the serialization boundary — `proto`
// the generated tonic contract (consumed cross-crate by `coxswain-bin` and by this
// crate's benches via `coxswain_discovery::proto::v1`), `wire` the encode/decode
// codec whose symmetric surface is exercised by round-trip tests. Every other
// module is reachable only through the crate-root re-exports below
// (`pub(crate)`-by-default, CLAUDE.md).
pub mod proto;
pub(crate) mod registry;
pub(crate) mod relay;
pub(crate) mod server;
pub(crate) mod subscription;
pub(crate) mod svid;
pub(crate) mod transport;
pub(crate) mod upstream;
pub(crate) mod version;
pub mod wire;

#[cfg(test)]
mod tests;

pub use auth::{
    DiscoveryBootstrapClientTls, DiscoveryBootstrapServerTls, DiscoveryClientTls,
    DiscoveryServerTls, RotatingServerTls, SpiffeMatcher,
};
pub use bootstrap_client::{
    BootstrapClient, BootstrapClientConfig, BootstrapClientHandle, BootstrapRunner,
};
pub use bootstrap_server::{
    BootstrapService, NoOpRejectHook, RejectHook, ResolvedUpstream, UpstreamResolverConfig,
};
pub use client::{
    DiscoveryClient, DiscoveryClientConfig, DiscoverySupervisor, Supervisor,
    UpstreamDirectiveHandler,
};
pub use error::{AuthError, DiscoveryError, WireError};
// `materialize` is `pub(crate)`, but its view type + builder are the one internal
// surface the external benches (`benches/relay_apply.rs`) legitimately need, so
// they ride the crate-root re-export like everything else.
pub use materialize::{MaterializedView, materialize};
pub use relay::{RelayUpstream, namespace_relay, shared_relay};
pub use server::{
    DenyAll, DiscoveryService, ProvisionedRelayAuthorizer, RelayAuthzConfig, ScopeAuthorizer,
    SnapshotSource,
};
pub use subscription::Scope;
pub use svid::{SharedSvid, SvidMaterial};
pub use transport::serve_discovery_with_tls;
pub use upstream::{
    SharedUpstream, UpstreamNames, UpstreamPolicy, UpstreamRejection, UpstreamTarget,
    expected_server_matcher, namespace_from_service_dns,
};
pub use version::{ContentHash, WIRE_VERSION};
pub use wire::{scope_from_wire, scope_to_wire};

/// Decode cap the server applies to every inbound [`proto::v1::ClientMessage`]
/// (`transport::serve_discovery_with_tls`).
///
/// Every arm is small except `RosterReport` (#585), which scales with one
/// relay's leaf count. Each entry is the leaf's convergence state (~150 bytes)
/// plus its folded `HealthReport` (#677) — the reporting build's version and
/// each subsystem's named checks, so a proxy's single one-check subsystem adds
/// well under 100 bytes and only a `Degraded`/`Failed` reason string makes an
/// entry meaningfully larger. Call it ~250 bytes/entry healthy, and 1 MiB still
/// covers a relay with a few thousand leaves. tonic's crate default is 4 MiB
/// with no explicit bound at all; this is a named, intentional cap rather than
/// an implicit one. The stream is mTLS+SPIFFE-gated, so this is bug
/// containment, not an untrusted-input bound.
pub(crate) const MAX_CLIENT_MESSAGE_BYTES: usize = 1024 * 1024;

/// Decode cap the client applies to every inbound [`proto::v1::ServerMessage`]
/// (`client::DiscoveryClient`, `bootstrap_client`).
///
/// `Snapshot` is not chunked — one message carries every `Resource` in the
/// subscribed scope (route hosts, PEM cert stores, all endpoints). tonic 0.14
/// defaults `max_send_message_size` to unbounded but `max_decode_message_size`
/// to 4 MiB (`DEFAULT_MAX_RECV_MESSAGE_SIZE`), so an unbounded server and a
/// 4 MiB client cap is a live convergence cliff on a large cluster: the
/// controller sends a snapshot the client then refuses to decode, Nacks,
/// reconnects, and never converges. 64 MiB raises the cliff to a size no
/// realistic cluster snapshot approaches while still bounding a malfunctioning
/// or malicious peer.
pub(crate) const MAX_SERVER_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

// Both must be non-zero (a zero cap would reject every message, including a
// legitimately empty one), and the client cap — bounding a whole-world
// Snapshot — must exceed the server cap, which bounds only a single small
// ClientMessage arm. A `const` assertion checks this at compile time on every
// build, not just under `cargo test`.
const _: () = assert!(MAX_CLIENT_MESSAGE_BYTES > 0);
const _: () = assert!(MAX_SERVER_MESSAGE_BYTES > 0);
const _: () = assert!(MAX_SERVER_MESSAGE_BYTES > MAX_CLIENT_MESSAGE_BYTES);

/// Bench-only apply surface — exists **solely** for `benches/delta_apply.rs`,
/// which compiles as an external crate and so cannot reach the `pub(crate)`
/// `apply` pipeline directly. Deliberately `#[doc(hidden)]`; **not** public
/// API — nothing outside the bench may depend on it, and it is exempt from the
/// stability guarantees the rest of the crate root carries. It exposes only a
/// self-contained apply [`bench_internals::Harness`] (cache + the ten routing
/// cells) that returns the partition-reuse counts, keeping every `pub(crate)`
/// apply type internal.
#[doc(hidden)]
pub mod bench_internals {
    use crate::apply::{ResourceCache, SnapshotCells, apply_message};
    use crate::error::WireError;
    use crate::proto::v1 as p;
    use coxswain_core::listener_status::GatewayListenerStatusHandle;
    use coxswain_core::routing::{
        SharedGatewayRoutingTable, SharedIngressRoutingTable, SharedTcpRouteTable,
        SharedTlsPassthroughTable, SharedUdpRouteTable,
    };
    use coxswain_core::tls::{SharedClientCertStore, SharedListenerHostnames, SharedPortTlsStore};

    /// Owns a materialized cache plus the ten routing cells the apply path
    /// publishes, so a bench can apply successive messages against a warm world
    /// and read back the partition-reuse accounting. Mirrors the inline-test
    /// `Cells` helper, made non-`#[cfg(test)]` for the bench.
    pub struct Harness {
        cache: ResourceCache,
        ingress: SharedIngressRoutingTable,
        gateway: SharedGatewayRoutingTable,
        tls: SharedPortTlsStore,
        client_certs: SharedClientCertStore,
        status: GatewayListenerStatusHandle,
        listener_hostnames: SharedListenerHostnames,
        passthrough: SharedTlsPassthroughTable,
        terminate: SharedTlsPassthroughTable,
        tcp: SharedTcpRouteTable,
        udp: SharedUdpRouteTable,
    }

    impl Default for Harness {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Harness {
        /// A fresh harness: empty cache, empty cells.
        #[must_use]
        pub fn new() -> Self {
            Self {
                cache: ResourceCache::new(),
                ingress: SharedIngressRoutingTable::new(),
                gateway: SharedGatewayRoutingTable::new(),
                tls: SharedPortTlsStore::new(),
                client_certs: SharedClientCertStore::new(),
                status: GatewayListenerStatusHandle::new(),
                listener_hostnames: SharedListenerHostnames::new(),
                passthrough: SharedTlsPassthroughTable::new(),
                terminate: SharedTlsPassthroughTable::new(),
                tcp: SharedTcpRouteTable::new(),
                udp: SharedUdpRouteTable::new(),
            }
        }

        /// Apply one wire message against the harness, returning
        /// `(partitions_recompiled, partitions_reused)` — the partition-reuse
        /// payoff the bench quantifies.
        ///
        /// # Errors
        ///
        /// Propagates any [`WireError`] from the apply pipeline (bad version,
        /// unkeyable resource, compile failure, …).
        #[must_use = "the bench asserts on the reuse counts; dropping them hides a Nack"]
        pub fn apply(
            &mut self,
            msg: &p::Snapshot,
            expect_full: bool,
        ) -> Result<(u64, u64), WireError> {
            // Disjoint field borrows: the cells bundle borrows nine cells
            // immutably while the cache is borrowed mutably — different fields,
            // so the borrow checker permits both from one `&mut self`.
            let cells = SnapshotCells {
                ingress: &self.ingress,
                gateway: &self.gateway,
                tls: &self.tls,
                client_certs: &self.client_certs,
                status: &self.status,
                listener_hostnames: &self.listener_hostnames,
                passthrough: &self.passthrough,
                terminate: &self.terminate,
                tcp: &self.tcp,
                udp: &self.udp,
            };
            let stats = apply_message(&mut self.cache, msg, cells, expect_full, true)?;
            Ok((stats.partitions_recompiled, stats.partitions_reused))
        }
    }

    /// The wire version stamp for a resource set — the same order-independent
    /// combination of per-resource hashes a real server stamps (F6), so the
    /// client's version self-check passes on bench and test fixtures.
    ///
    /// The single home of this test/bench convenience: it is the one definition
    /// reachable by BOTH the external bench crate (via this doc-hidden module) AND
    /// the crate's inline `#[cfg(test)]` modules (which import it from here). The
    /// version *formula* itself still lives once in
    /// [`crate::version::ContentHash::from_per_resource`]; production feeds that
    /// directly from already-computed per-resource digests (the server in
    /// `materialize::build_view`, the client in `apply`) and never routes through
    /// this whole-resource convenience.
    #[must_use]
    pub fn snapshot_version(resources: &[p::Resource]) -> String {
        let hashes: Vec<String> = resources
            .iter()
            .map(crate::wire::resource::resource_hash)
            .collect();
        crate::version::ContentHash::from_per_resource(hashes.iter().map(String::as_str))
            .as_str()
            .to_owned()
    }

    /// Bench-only relay demux surface (#621) — drives the real `NamespaceDemux`
    /// apply path (per-key digest retention + the trusted per-Gateway
    /// reconstruction that skips the redundant self-check) so
    /// `benches/relay_apply.rs` can time it without reaching the `pub(crate)`
    /// type. Same `#[doc(hidden)]`, non-API status as [`Harness`].
    pub struct RelayHarness {
        demux: crate::relay::NamespaceDemux,
        expect_full: bool,
    }

    impl Default for RelayHarness {
        fn default() -> Self {
            Self::new()
        }
    }

    impl RelayHarness {
        /// A fresh demux with no namespace world applied yet.
        #[must_use]
        pub fn new() -> Self {
            Self {
                demux: crate::relay::NamespaceDemux::new(),
                expect_full: true,
            }
        }

        /// Apply one `Scope::Namespace` wire message. The first call must be a
        /// full; each later call is a delta folded onto the retained world.
        ///
        /// # Errors
        ///
        /// Propagates any [`WireError`] from the demux apply path (version
        /// mismatch, unkeyable resource, compile failure, …).
        pub fn apply(&mut self, msg: &p::Snapshot) -> Result<(), WireError> {
            use crate::apply::SnapshotApplier as _;
            let out = self.demux.apply(msg, self.expect_full).map(|_| ());
            self.expect_full = false;
            out
        }
    }
}
