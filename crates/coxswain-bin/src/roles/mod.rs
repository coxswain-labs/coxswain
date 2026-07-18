//! Pod-role entry points dispatched from [`crate::run`].
//!
//! Each role wires a disjoint slice of the runtime: `controller` the leader-elected
//! status writer, `proxy` the read-only data plane, `relay` the Kube-free discovery
//! fan-out node. Shared assembly lives in [`crate::wiring`], [`crate::services`],
//! and [`crate::discovery`].

pub(crate) mod controller;
pub(crate) mod proxy;
pub(crate) mod relay;
