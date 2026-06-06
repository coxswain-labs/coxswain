use crate::reconciler::{IngressDefaultBackend, IngressDefaultBackendParseError};

#[test]
fn happy_path() {
    let b: IngressDefaultBackend = "default/echo:80".parse().unwrap();
    assert_eq!(b.namespace, "default");
    assert_eq!(b.name, "echo");
    assert_eq!(b.port, 80);
}

#[test]
fn missing_colon_returns_missing_port() {
    let err = "default/echo".parse::<IngressDefaultBackend>().unwrap_err();
    assert!(matches!(err, IngressDefaultBackendParseError::MissingPort));
}

#[test]
fn missing_slash_returns_missing_namespace() {
    let err = "defaultecho:80"
        .parse::<IngressDefaultBackend>()
        .unwrap_err();
    assert!(matches!(
        err,
        IngressDefaultBackendParseError::MissingNamespace
    ));
}

#[test]
fn empty_namespace_returns_empty_component() {
    let err = "/echo:80".parse::<IngressDefaultBackend>().unwrap_err();
    assert!(matches!(
        err,
        IngressDefaultBackendParseError::EmptyComponent
    ));
}

#[test]
fn empty_name_returns_empty_component() {
    let err = "default/:80".parse::<IngressDefaultBackend>().unwrap_err();
    assert!(matches!(
        err,
        IngressDefaultBackendParseError::EmptyComponent
    ));
}

#[test]
fn non_numeric_port_returns_invalid_port() {
    let err = "default/echo:abc"
        .parse::<IngressDefaultBackend>()
        .unwrap_err();
    assert!(matches!(
        err,
        IngressDefaultBackendParseError::InvalidPort(s) if s == "abc"
    ));
}

#[test]
fn port_overflow_returns_invalid_port() {
    let err = "default/echo:2147483648"
        .parse::<IngressDefaultBackend>()
        .unwrap_err();
    assert!(matches!(
        err,
        IngressDefaultBackendParseError::InvalidPort(_)
    ));
}

#[test]
fn colon_in_service_name_uses_last_colon_as_port_separator() {
    // rsplit_once(':') splits on the last colon; "ns/svc:extra:80" → ns_name="ns/svc:extra", port=80
    let b: IngressDefaultBackend = "ns/svc:extra:80".parse().unwrap();
    assert_eq!(b.namespace, "ns");
    assert_eq!(b.name, "svc:extra");
    assert_eq!(b.port, 80);
}
