//! Leader-election identifiers shared across crates.
//!
//! The controller's HA truth-source is a `coordination.k8s.io` `Lease` in the
//! install namespace whose `spec.holderIdentity` is the leader pod's name.
//!
//! This lives in `coxswain-core` rather than `coxswain-controller` because the
//! lease is read by crates that must not depend on the controller —
//! `coxswain-admin` resolves the leader from it to answer "which pod is the
//! leader" without probing peers, and the e2e harness targets it to kill the
//! leader deterministically. Before this module each of those kept its own
//! copy of the string, annotated as mirroring the controller's.

use std::sync::Arc;

use crate::shared::Shared;

/// Name of the controller's leader-election `Lease`, in the install namespace.
///
/// Reading `spec.holderIdentity` off this object is the authoritative answer to
/// "which replica is the leader". It beats asking each pod over HTTP on two
/// counts: it resolves even when the leader is unreachable, and it is fresher —
/// a pod's self-reported flag is a cached value refreshed on its own renewal
/// tick, so it lags the lease by up to one interval and reads stale across a
/// failover.
pub const LEASE_NAME: &str = "coxswain-leader-lock";

/// Pod name of the current lease holder, or `None` when leadership is unknown.
///
/// Written by the controller's lease-renewal loop, which already holds the
/// `Lease` object on every tick — publishing the holder from there costs **no
/// additional apiserver traffic** and is at most one renewal interval stale
/// (5 s by default, well inside the 15 s TTL). The admin aggregator reads it to
/// attribute leadership in the fleet view.
///
/// A per-request `GET` on the Lease would be the obvious alternative and is
/// worse on three counts: it adds an apiserver round trip to every UI poll, it
/// puts a network call on a request path that otherwise only reads local
/// snapshots, and it makes the aggregator's unit tests reach for a cluster.
///
/// `None` means "no leader right now, or not yet observed" — a genuine
/// leaderless window and a not-yet-run lease loop are indistinguishable here,
/// and both should render as "no leader" rather than a guess.
pub type LeaderIdentityCell = Shared<Option<Arc<str>>>;
