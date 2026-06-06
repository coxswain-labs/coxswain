use crate::accept::*;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn trusted_sources_contains_ip_in_range() {
    let net: ipnet::IpNet = "192.168.1.0/24".parse().unwrap();
    let ts = TrustedSources::new(vec![net]);
    assert!(ts.contains(&"192.168.1.100".parse::<IpAddr>().unwrap()));
    assert!(!ts.contains(&"10.0.0.1".parse::<IpAddr>().unwrap()));
}

#[test]
fn trusted_sources_loopback() {
    let net: ipnet::IpNet = "127.0.0.1/32".parse().unwrap();
    let ts = TrustedSources::new(vec![net]);
    assert!(ts.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(!ts.contains(&"192.168.0.1".parse::<IpAddr>().unwrap()));
}

#[test]
fn trusted_sources_empty_rejects_all() {
    let ts = TrustedSources::new(vec![]);
    assert!(!ts.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
}
