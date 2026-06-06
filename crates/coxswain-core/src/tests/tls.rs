use crate::tls::*;
use std::sync::Arc;

fn cert(source: &str) -> Arc<TlsCert> {
    Arc::new(TlsCert::new(
        b"cert".to_vec(),
        b"key".to_vec(),
        source.to_string(),
    ))
}

#[test]
fn exact_host_lookup() {
    let mut b = TlsStoreBuilder::new();
    b.add_cert("example.com", cert("ns/s1"));
    let store = b.build();
    assert!(store.find_cert("example.com").is_some());
    assert!(store.find_cert("other.com").is_none());
}

#[test]
fn wildcard_host_lookup() {
    let mut b = TlsStoreBuilder::new();
    b.add_cert("*.example.com", cert("ns/s1"));
    let store = b.build();
    assert!(store.find_cert("api.example.com").is_some());
    assert!(store.find_cert("example.com").is_none());
    assert!(store.find_cert("a.b.example.com").is_none());
}

#[test]
fn exact_beats_wildcard_on_sni() {
    let mut b = TlsStoreBuilder::new();
    b.add_cert("api.example.com", cert("exact"));
    b.add_cert("*.example.com", cert("wildcard"));
    let store = b.build();
    let found = store.find_cert("api.example.com").unwrap();
    assert_eq!(found.source, "exact");
}

#[test]
fn no_match_returns_none() {
    let store = TlsStoreBuilder::new().build();
    assert!(store.find_cert("example.com").is_none());
}

#[test]
fn catchall_host_becomes_default() {
    let mut b = TlsStoreBuilder::new();
    b.add_cert("", cert("ns/s1"));
    b.add_cert("*", cert("ns/s2")); // last writer wins
    let store = b.build();
    assert_eq!(store.cert_count(), 1);
    // Default is served for any SNI that has no exact/wildcard match.
    assert_eq!(
        store.find_cert("anything.example.com").unwrap().source,
        "ns/s2"
    );
}

#[test]
fn default_cert_is_fallback_only() {
    let mut b = TlsStoreBuilder::new();
    b.add_cert("example.com", cert("exact"));
    b.add_cert("", cert("default"));
    let store = b.build();
    assert_eq!(store.find_cert("example.com").unwrap().source, "exact");
    assert_eq!(store.find_cert("other.com").unwrap().source, "default");
}

#[test]
fn last_writer_wins_on_duplicate_exact_host() {
    let mut b = TlsStoreBuilder::new();
    b.add_cert("example.com", cert("first"));
    b.add_cert("example.com", cert("second"));
    let store = b.build();
    assert_eq!(store.find_cert("example.com").unwrap().source, "second");
}

#[test]
fn last_writer_wins_on_duplicate_wildcard() {
    let mut b = TlsStoreBuilder::new();
    b.add_cert("*.example.com", cert("first"));
    b.add_cert("*.example.com", cert("second"));
    let store = b.build();
    assert_eq!(store.find_cert("api.example.com").unwrap().source, "second");
}

#[test]
fn equal_stores_same_pem_different_source() {
    let mut b1 = TlsStoreBuilder::new();
    b1.add_cert("example.com", cert("ns/s1"));
    b1.add_cert("*.api.example.com", cert("ns/s2"));

    // Source strings differ — should still be equal because PEM bytes match.
    let mut b2 = TlsStoreBuilder::new();
    b2.add_cert("example.com", cert("ns/different-source"));
    b2.add_cert("*.api.example.com", cert("ns/s2"));

    assert_eq!(b1.build(), b2.build());
}

#[test]
fn different_cert_bytes_not_equal() {
    let cert_a = Arc::new(TlsCert::new(
        b"cert-a".to_vec(),
        b"key".to_vec(),
        "ns/s1".to_string(),
    ));
    let cert_b = Arc::new(TlsCert::new(
        b"cert-b".to_vec(),
        b"key".to_vec(),
        "ns/s1".to_string(),
    ));

    let mut b1 = TlsStoreBuilder::new();
    b1.add_cert("example.com", cert_a);

    let mut b2 = TlsStoreBuilder::new();
    b2.add_cert("example.com", cert_b);

    assert_ne!(b1.build(), b2.build());
}

#[test]
fn wildcard_sorted_longest_suffix_first() {
    let mut b = TlsStoreBuilder::new();
    b.add_cert("*.example.com", cert("short"));
    b.add_cert("*.api.example.com", cert("long"));
    let store = b.build();
    assert_eq!(
        store.find_cert("v1.api.example.com").unwrap().source,
        "long"
    );
    assert_eq!(store.find_cert("web.example.com").unwrap().source, "short");
}
