use super::*;
use std::net::SocketAddr;

// ── BackendGroup round-robin tests ────────────────────────────────────────────

#[test]
fn round_robin_cycles() {
    let addrs: Vec<SocketAddr> = vec![
        "10.0.0.1:80".parse().unwrap(),
        "10.0.0.2:80".parse().unwrap(),
        "10.0.0.3:80".parse().unwrap(),
    ];
    let up = BackendGroup::new("svc".to_string(), addrs.clone());
    let results: Vec<SocketAddr> = (0..6).map(|_| up.next_endpoint().unwrap()).collect();
    assert_eq!(
        results,
        [addrs[0], addrs[1], addrs[2], addrs[0], addrs[1], addrs[2]]
    );
}

#[test]
fn weighted_round_robin_distributes_proportionally() {
    let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
    let a2: SocketAddr = "10.0.0.2:80".parse().unwrap();
    let b1: SocketAddr = "10.0.1.1:80".parse().unwrap();

    // Backend A: 2 pods, weight 4.  Backend B: 1 pod, weight 1.
    // Expected: P(A) = 4/5 = 80%.
    let up = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1, a2], 4), (vec![b1], 1)]);

    let n = 1000;
    let mut a_count = 0usize;
    let mut b_count = 0usize;
    for _ in 0..n {
        let addr = up.next_endpoint().unwrap();
        if addr == a1 || addr == a2 {
            a_count += 1;
        } else if addr == b1 {
            b_count += 1;
        }
    }
    assert_eq!(a_count + b_count, n);
    // Allow ±5% tolerance around the expected 80/20 split.
    let a_ratio = a_count as f64 / n as f64;
    assert!(
        (0.75..=0.85).contains(&a_ratio),
        "backend A ratio {a_ratio:.2} out of expected 0.75–0.85"
    );
}

#[test]
fn weighted_zero_weight_backend_gets_no_traffic() {
    let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
    let b1: SocketAddr = "10.0.1.1:80".parse().unwrap();

    let up = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1], 0), (vec![b1], 1)]);
    for _ in 0..100 {
        assert_eq!(up.next_endpoint().unwrap(), b1);
    }
}

#[test]
fn weighted_all_zero_is_empty() {
    let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
    let up = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1], 0)]);
    assert!(up.next_endpoint().is_none());
}

#[test]
fn weighted_equal_weights_uniform() {
    let a1: SocketAddr = "10.0.0.1:80".parse().unwrap();
    let b1: SocketAddr = "10.0.1.1:80".parse().unwrap();

    // Equal weights → after GCD reduction both get 1 slot → 50/50.
    let up = BackendGroup::weighted("ns/svc".to_string(), vec![(vec![a1], 5), (vec![b1], 5)]);
    let results: Vec<SocketAddr> = (0..4).map(|_| up.next_endpoint().unwrap()).collect();
    // slots = [0, 1] after reduction; cycling: a1, b1, a1, b1
    assert_eq!(results, [a1, b1, a1, b1]);
}

// ── BackendProtocol / parse_app_protocol tests ────────────────────────────────

#[test]
fn parse_app_protocol_known_values() {
    assert_eq!(
        parse_app_protocol("kubernetes.io/h2c"),
        BackendProtocol::H2c
    );
    assert_eq!(
        parse_app_protocol("kubernetes.io/ws"),
        BackendProtocol::WebSocket
    );
    assert_eq!(
        parse_app_protocol("kubernetes.io/wss"),
        BackendProtocol::WebSocketTls
    );
    assert_eq!(parse_app_protocol("https"), BackendProtocol::Https);
}

#[test]
fn parse_app_protocol_defaults_to_http1() {
    assert_eq!(parse_app_protocol(""), BackendProtocol::Http1);
    assert_eq!(parse_app_protocol("http"), BackendProtocol::Http1);
    assert_eq!(
        parse_app_protocol("example.com/custom"),
        BackendProtocol::Http1
    );
}

// ── UpstreamTls / with_tls round-trip tests ───────────────────────────────────

#[test]
fn backend_group_with_tls_system_round_trip() {
    let addr: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let sni: Arc<str> = Arc::from("backend.example.com");
    let tls = Arc::new(UpstreamTls::new(sni.clone(), UpstreamCa::System, 42));
    let group = BackendGroup::new("svc".to_string(), vec![addr]).with_tls(Arc::clone(&tls));

    let got = group.upstream_tls().expect("TLS should be attached");
    assert_eq!(&*got.sni, "backend.example.com");
    assert_eq!(got.group_key, 42);
    assert!(matches!(got.ca, UpstreamCa::System));
}

#[test]
fn backend_group_with_tls_bundle_round_trip() {
    let addr: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let pem: Arc<[u8]> = Arc::from(b"-----BEGIN CERTIFICATE-----\nfake\n".as_slice());
    let tls = Arc::new(UpstreamTls::new(
        Arc::from("backend.example.com"),
        UpstreamCa::Bundle(Arc::clone(&pem)),
        99,
    ));
    let group = BackendGroup::new("svc".to_string(), vec![addr]).with_tls(Arc::clone(&tls));

    let got = group.upstream_tls().expect("TLS should be attached");
    assert!(matches!(&got.ca, UpstreamCa::Bundle(p) if p.as_ref() == pem.as_ref()));
}

#[test]
fn backend_group_without_tls_returns_none() {
    let addr: SocketAddr = "10.0.0.1:80".parse().unwrap();
    let group = BackendGroup::new("svc".to_string(), vec![addr]);
    assert!(group.upstream_tls().is_none());
}

#[test]
fn upstream_tls_size_unchanged() {
    // BackendGroup now has one extra Option<Arc<UpstreamTls>> = 8 bytes;
    // but RouteEntry holds Arc<BackendGroup>, so RouteEntry size is unaffected.
    static_assertions::assert_eq_size!(RouteEntry, [u8; 176]);
}

#[test]
fn upstream_with_protocol_round_trips() {
    let u = BackendGroup::new("ns/svc".to_string(), vec![]).with_protocol(BackendProtocol::H2c);
    assert_eq!(u.protocol(), BackendProtocol::H2c);
}

#[test]
fn upstream_default_protocol_is_http1() {
    let u = BackendGroup::new("ns/svc".to_string(), vec![]);
    assert_eq!(u.protocol(), BackendProtocol::Http1);
}
