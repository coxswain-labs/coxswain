//! [`SnapshotSource`] — the routing-table snapshot cells the discovery server reads.
//!
//! Populated in `coxswain-bin` from `StatusWriter::outputs`; the server clones it
//! per connection (tonic requires `Clone`) and never touches the Kubernetes API at
//! serve time.

use coxswain_core::dedicated_registry::DedicatedRoutingRegistry;
use coxswain_core::listener_status::GatewayListenerStatusHandle;
use coxswain_core::publish_index::GatewayPublishIndexHandle;
use coxswain_core::routing::{
    SharedGatewayRoutingTable, SharedIngressRoutingTable, SharedTcpRouteTable,
    SharedTlsPassthroughTable, SharedUdpRouteTable,
};
use coxswain_core::tls::{SharedClientCertStore, SharedPortTlsStore};

// ── SnapshotSource ────────────────────────────────────────────────────────────

/// The routing-table [`Shared`] cells the server reads to build snapshots (the
/// nine shared L7/status/L4 cells, plus the per-Gateway dedicated registry and the
/// publish-sequence index).
///
/// Populated in `coxswain-bin` from `StatusWriter::outputs`; no K8s API access
/// happens at serve time.
///
/// [`Shared`]: coxswain_core::Shared
// intentionally open: field-literal constructed in coxswain-bin
#[derive(Clone)]
pub struct SnapshotSource {
    /// Ingress routing table shared cell.
    pub ingress: SharedIngressRoutingTable,
    /// Gateway-API routing table shared cell.
    pub gateway: SharedGatewayRoutingTable,
    /// TLS certificate store shared cell.
    pub tls: SharedPortTlsStore,
    /// Client-certificate mTLS config store shared cell.
    pub client_certs: SharedClientCertStore,
    /// Per-Gateway listener status map. Serialised into the
    /// `listener_status` wire field so proxy nodes can drive dynamic
    /// Gateway listener port bind/unbind without Kubernetes API access.
    pub listener_status: GatewayListenerStatusHandle,
    /// Per-cut-over-Gateway routing snapshots, keyed by Gateway [`ObjectKey`](coxswain_core::ownership::ObjectKey).
    /// Read when a client subscribes with [`Scope::Gateway`](crate::subscription::Scope::Gateway); all the other
    /// routing cells (the L7/status cells above and the four L4 tables below)
    /// serve [`Scope::SharedPool`](crate::subscription::Scope::SharedPool) and deliberately exclude cut-over Gateways. The
    /// shared reconciler is the sole writer.
    pub dedicated: DedicatedRoutingRegistry,
    /// SNI-keyed TLS passthrough routing table for TLSRoute / GEP-2643 (#70).
    /// Only populated for [`Scope::SharedPool`](crate::subscription::Scope::SharedPool) subscribers; dedicated proxies
    /// receive an empty table (TLSRoutes are shared-pool only).
    pub passthrough_routes: SharedTlsPassthroughTable,
    /// SNI-keyed TLS terminate routing table for TLSRouteModeTerminate (#481).
    /// Only populated for [`Scope::SharedPool`](crate::subscription::Scope::SharedPool) subscribers; dedicated proxies
    /// receive an empty table (TLSRoutes are shared-pool only).
    pub terminate_routes: SharedTlsPassthroughTable,
    /// Port-keyed TCP routing table for TCPRoute / GEP-1901 (#505).
    /// Only populated for [`Scope::SharedPool`](crate::subscription::Scope::SharedPool) subscribers; dedicated proxies
    /// receive an empty table (TCPRoutes are shared-pool only).
    pub tcp_routes: SharedTcpRouteTable,
    /// Port-keyed UDP routing table for UDPRoute / GEP-2645 (#506).
    /// Only populated for [`Scope::SharedPool`](crate::subscription::Scope::SharedPool) subscribers; dedicated proxies
    /// receive an empty table (UDPRoutes are shared-pool only).
    pub udp_routes: SharedUdpRouteTable,
    /// Per-Gateway publish-sequence index (#531). The server captures its
    /// counter **before** loading any cell for a snapshot build; a node that
    /// Acks that snapshot has therefore applied every rebuild stamped at a
    /// sequence `<=` the captured value — the content-convergence input to
    /// the `Programmed` ack gate.
    pub publish: GatewayPublishIndexHandle,
}
