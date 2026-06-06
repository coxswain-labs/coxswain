macro_rules! fixture {
    ($path:literal) => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/ingress/", $path)
    };
}

pub const PATH_MATCHING: &str = fixture!("path_matching.yaml");
pub const DEFAULT_BACKEND: &str = fixture!("default_backend.yaml");
pub const DEFAULT_BACKEND_ONLY: &str = fixture!("default_backend_only.yaml");
pub const TLS_TERMINATION: &str = fixture!("tls_termination.yaml");
pub const TLS_NO_HOSTS: &str = fixture!("tls_no_hosts.yaml");
pub const CERT_MANAGER: &str = fixture!("cert_manager.yaml");
pub const WILDCARD_HOST: &str = fixture!("wildcard_host.yaml");
pub const NAMED_PORT: &str = fixture!("named_port.yaml");
pub const DEFAULT_CLASS: &str = fixture!("default_class.yaml");
