//! Validated configuration for the leader-election controller.

use crate::ingress::IngressPorts;
use std::net::IpAddr;
use std::time::Duration;
use thiserror::Error;

/// The external address written to `Ingress.status.loadBalancer.ingress[0]`
/// and `Gateway.status.addresses[0]`.
///
/// Parsed from `--status-address` at startup: if the value is a valid
/// `IpAddr` it becomes `Ip`, otherwise it is treated as a DNS hostname.
#[non_exhaustive]
#[derive(Debug)]
pub enum StatusAddress {
    /// A bare IP address written to `.ip` in the status block.
    Ip(IpAddr),
    /// A DNS hostname written to `.hostname` in the status block.
    Hostname(String),
}

/// Leader-election lease timing, validated as a pair.
///
/// Grouped so [`ControllerConfig::new`] stays under the workspace
/// `clippy::too_many_arguments` threshold and the lease-related cross-checks
/// (renewal ≤ TTL/3) live next to the values they constrain.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct LeaseSettings {
    /// How long the lease stays valid without renewal.
    pub ttl: Duration,
    /// How often the active leader renews its lease.
    pub renew_interval: Duration,
}

impl LeaseSettings {
    /// Construct a `LeaseSettings` from the TTL and renewal cadence.
    ///
    /// The constructor does no validation — the renewal/TTL ratio check runs
    /// inside [`ControllerConfig::new`] so callers see one consolidated error
    /// type.
    #[must_use]
    pub fn new(ttl: Duration, renew_interval: Duration) -> Self {
        Self {
            ttl,
            renew_interval,
        }
    }
}

/// Error returned by [`ControllerConfig::new`].
#[derive(Debug, Error)]
pub enum ControllerConfigError {
    /// The lease renewal interval is too fast relative to the TTL.
    #[error("lease.renew_interval ({renew:?}) must be at most 1/3 of lease.ttl ({ttl:?})")]
    LeaseRatioTooFast {
        /// The configured lease TTL.
        ttl: Duration,
        /// The configured renewal interval that is too fast.
        renew: Duration,
    },
    /// `--status-address` was provided but the value is empty after trimming.
    #[error("status_address must not be empty")]
    EmptyStatusAddress,
}

/// Configuration for the leader-election controller.
///
/// Validated on construction: `lease.renew_interval * 3` must not exceed
/// `lease.ttl`, which keeps the renewal rate safely below the threshold where
/// a live leader could be evicted by a standby.
#[non_exhaustive]
#[derive(Debug)]
pub struct ControllerConfig {
    /// `GatewayClass.spec.controllerName` this instance claims.
    pub controller_name: String,
    /// Pod name used as the lease holder identity.
    pub pod_name: String,
    /// Namespace in which the leader-election `Lease` resource is created.
    pub pod_namespace: String,
    /// Leader-election lease TTL and renewal cadence.
    pub lease: LeaseSettings,
    /// When set, scope namespaced watches to this namespace. When `None`, watch cluster-wide.
    pub watch_namespace: Option<String>,
    /// When set, the leader writes this address to every owned
    /// `Ingress.status.loadBalancer.ingress[0]` and `Gateway.status.addresses[0]`
    /// after each watch event.
    pub status_address: Option<StatusAddress>,
    /// Ports reserved for the Ingress data plane via `--proxy-http-port` and
    /// `--proxy-https-port`. Gateway listeners requesting one of these ports
    /// are surfaced as `Programmed=False, reason=PortUnavailable` since the
    /// `GatewayProxy` cannot bind a port already claimed by the `IngressProxy`.
    pub ingress_ports: IngressPorts,
}

impl ControllerConfig {
    /// Validate and construct a [`ControllerConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`ControllerConfigError::LeaseRatioTooFast`] when
    /// `lease.renew_interval * 3 > lease.ttl` (the renewal rate is too fast
    /// relative to the TTL, risking eviction of a live leader by a standby).
    ///
    /// Returns [`ControllerConfigError::EmptyStatusAddress`] when `status_address`
    /// is `Some` but is empty after trimming.
    #[must_use = "the validated config must be used or the validation is pointless"]
    pub fn new(
        controller_name: String,
        pod_name: String,
        pod_namespace: String,
        lease: LeaseSettings,
        watch_namespace: Option<String>,
        status_address: Option<String>,
        ingress_ports: IngressPorts,
    ) -> Result<Self, ControllerConfigError> {
        if lease.renew_interval * 3 > lease.ttl {
            return Err(ControllerConfigError::LeaseRatioTooFast {
                ttl: lease.ttl,
                renew: lease.renew_interval,
            });
        }
        let status_address = status_address
            .map(|s| {
                let s = s.trim().to_string();
                if s.is_empty() {
                    return Err(ControllerConfigError::EmptyStatusAddress);
                }
                match s.parse::<IpAddr>() {
                    Ok(ip) => Ok(StatusAddress::Ip(ip)),
                    Err(_) => Ok(StatusAddress::Hostname(s)),
                }
            })
            .transpose()?;
        Ok(Self {
            controller_name,
            pod_name,
            pod_namespace,
            lease,
            watch_namespace,
            status_address,
            ingress_ports,
        })
    }
}
