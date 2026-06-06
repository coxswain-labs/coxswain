use std::net::IpAddr;
use std::time::Duration;
use thiserror::Error;

/// The external address written to `Ingress.status.loadBalancer.ingress[0]`
/// and `Gateway.status.addresses[0]`.
///
/// Parsed from `--status-address` at startup: if the value is a valid
/// `IpAddr` it becomes `Ip`, otherwise it is treated as a DNS hostname.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(ttl_secs: u64, renew_secs: u64) -> Result<ControllerConfig, ControllerConfigError> {
        ControllerConfig::new(
            "ctrl".to_string(),
            "pod".to_string(),
            "ns".to_string(),
            Duration::from_secs(ttl_secs),
            Duration::from_secs(renew_secs),
            None,
            None,
        )
    }

    #[test]
    fn lease_ratio_valid() {
        // renew * 3 == ttl is allowed (equal, not strictly greater)
        assert!(cfg(15, 5).is_ok());
    }

    #[test]
    fn lease_ratio_too_fast() {
        let err = cfg(15, 6).unwrap_err();
        assert!(matches!(
            err,
            ControllerConfigError::LeaseRatioTooFast { .. }
        ));
        assert!(err.to_string().contains("15s"));
        assert!(err.to_string().contains("6s"));
    }

    #[test]
    fn empty_status_address_is_error() {
        let err = ControllerConfig::new(
            "ctrl".to_string(),
            "pod".to_string(),
            "ns".to_string(),
            Duration::from_secs(15),
            Duration::from_secs(5),
            None,
            Some("  ".to_string()),
        )
        .unwrap_err();
        assert!(matches!(err, ControllerConfigError::EmptyStatusAddress));
    }

    #[test]
    fn ip_status_address() {
        let cfg = ControllerConfig::new(
            "ctrl".to_string(),
            "pod".to_string(),
            "ns".to_string(),
            Duration::from_secs(15),
            Duration::from_secs(5),
            None,
            Some("127.0.0.1".to_string()),
        )
        .unwrap();
        assert!(matches!(cfg.status_address, Some(StatusAddress::Ip(_))));
    }

    #[test]
    fn hostname_status_address() {
        let cfg = ControllerConfig::new(
            "ctrl".to_string(),
            "pod".to_string(),
            "ns".to_string(),
            Duration::from_secs(15),
            Duration::from_secs(5),
            None,
            Some("my-host.example.com".to_string()),
        )
        .unwrap();
        assert!(matches!(
            cfg.status_address,
            Some(StatusAddress::Hostname(_))
        ));
    }
}
