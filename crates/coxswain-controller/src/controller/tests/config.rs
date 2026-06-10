use super::super::config::{ControllerConfig, ControllerConfigError, LeaseSettings, StatusAddress};
use coxswain_reflector::ingress::IngressPorts;
use std::time::Duration;

fn cfg(ttl_secs: u64, renew_secs: u64) -> Result<ControllerConfig, ControllerConfigError> {
    ControllerConfig::new(
        "ctrl".to_string(),
        "pod".to_string(),
        "ns".to_string(),
        LeaseSettings::new(
            Duration::from_secs(ttl_secs),
            Duration::from_secs(renew_secs),
        ),
        None,
        None,
        IngressPorts::new(Some(80), Some(443)),
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
        LeaseSettings::new(Duration::from_secs(15), Duration::from_secs(5)),
        None,
        Some("  ".to_string()),
        IngressPorts::new(Some(80), Some(443)),
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
        LeaseSettings::new(Duration::from_secs(15), Duration::from_secs(5)),
        None,
        Some("127.0.0.1".to_string()),
        IngressPorts::new(Some(80), Some(443)),
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
        LeaseSettings::new(Duration::from_secs(15), Duration::from_secs(5)),
        None,
        Some("my-host.example.com".to_string()),
        IngressPorts::new(Some(80), Some(443)),
    )
    .unwrap();
    assert!(matches!(
        cfg.status_address,
        Some(StatusAddress::Hostname(_))
    ));
}
