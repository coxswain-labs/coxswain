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
pub mod auth;
pub mod bootstrap_client;
pub mod bootstrap_server;
pub mod client;
pub mod error;
pub mod materialize;
pub mod metrics;
pub mod proto;
pub mod registry;
pub mod relay;
pub mod server;
pub mod subscription;
pub mod svid;
pub mod transport;
pub mod upstream;
pub mod version;
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
pub use bootstrap_server::{BootstrapService, NoOpRejectHook, RejectHook, UpstreamResolverConfig};
pub use client::{
    DiscoveryClient, DiscoveryClientConfig, DiscoverySupervisor, Supervisor,
    UpstreamDirectiveHandler,
};
pub use error::{AuthError, DiscoveryError, WireError};
pub use relay::{RelayUpstream, namespace_relay, shared_relay};
pub use server::{DiscoveryService, ProvisionedRelayAuthorizer, ScopeAuthorizer, SnapshotSource};
pub use subscription::Scope;
pub use svid::{SharedSvid, SvidMaterial};
pub use transport::serve_discovery_with_tls;
pub use upstream::{
    SharedUpstream, UpstreamTarget, expected_server_matcher, namespace_from_service_dns,
};
pub use version::{ContentHash, WIRE_VERSION};
pub use wire::{scope_from_wire, scope_to_wire};

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
    use coxswain_core::listener_status::SharedGatewayListenerStatus;
    use coxswain_core::routing::{
        SharedGatewayRoutingTable, SharedIngressRoutingTable, SharedTcpRouteTable,
        SharedTlsPassthroughTable, SharedUdpRouteTable,
    };
    use coxswain_core::tls::{SharedClientCertStore, SharedListenerHostnames, SharedPortTlsStore};

    /// Owns a materialized cache plus the ten routing cells the apply path
    /// publishes, so a bench can apply successive messages against a warm world
    /// and read back the partition-reuse accounting. Mirrors the inline-test
    /// `Cells` helper, made non-`#[cfg(test)]` for the bench.
    #[non_exhaustive]
    pub struct Harness {
        cache: ResourceCache,
        ingress: SharedIngressRoutingTable,
        gateway: SharedGatewayRoutingTable,
        tls: SharedPortTlsStore,
        client_certs: SharedClientCertStore,
        status: SharedGatewayListenerStatus,
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
                status: SharedGatewayListenerStatus::new(),
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
            let stats = apply_message(&mut self.cache, msg, cells, expect_full)?;
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
        let hashes = resources
            .iter()
            .map(crate::wire::resource::resource_hash)
            .collect();
        crate::version::ContentHash::from_per_resource(hashes)
            .as_str()
            .to_owned()
    }
}
