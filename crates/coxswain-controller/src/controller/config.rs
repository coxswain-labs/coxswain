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
    Ip(IpAddr),
    Hostname(String),
}

/// Error returned by [`ControllerConfig::new`].
#[derive(Debug, Error)]
pub enum ControllerConfigError {
    /// The lease renewal interval is too fast relative to the TTL.
    #[error("lease_renew_interval ({renew:?}) must be at most 1/3 of lease_ttl ({ttl:?})")]
    LeaseRatioTooFast { ttl: Duration, renew: Duration },
    /// `--status-address` was provided but the value is empty after trimming.
    #[error("status_address must not be empty")]
    EmptyStatusAddress,
}

/// Configuration for the leader-election controller.
///
/// Validated on construction: `lease_renew_interval * 3` must not exceed `lease_ttl`,
/// which keeps the renewal rate safely below the threshold where a live leader could
/// be evicted by a standby.
#[non_exhaustive]
#[derive(Debug)]
pub struct ControllerConfig {
    pub controller_name: String,
    pub pod_name: String,
    pub pod_namespace: String,
    pub lease_ttl: Duration,
    pub lease_renew_interval: Duration,
    /// When set, scope namespaced watches to this namespace. When `None`, watch cluster-wide.
    pub watch_namespace: Option<String>,
    /// When set, the leader writes this address to every owned
    /// `Ingress.status.loadBalancer.ingress[0]` and `Gateway.status.addresses[0]`
    /// after each watch event.
    pub status_address: Option<StatusAddress>,
}

impl ControllerConfig {
    #[must_use = "the validated config must be used or the validation is pointless"]
    pub fn new(
        controller_name: String,
        pod_name: String,
        pod_namespace: String,
        lease_ttl: Duration,
        lease_renew_interval: Duration,
        watch_namespace: Option<String>,
        status_address: Option<String>,
    ) -> Result<Self, ControllerConfigError> {
        if lease_renew_interval * 3 > lease_ttl {
            return Err(ControllerConfigError::LeaseRatioTooFast {
                ttl: lease_ttl,
                renew: lease_renew_interval,
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
            lease_ttl,
            lease_renew_interval,
            watch_namespace,
            status_address,
        })
    }
}
