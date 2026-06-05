use coxswain_core::routing::{BackendCaSource, BackendTlsConfig};
use pingora_core::protocols::tls::CaType;
use pingora_core::tls::x509::X509;
use std::any::Any;
use std::sync::Arc;

/// Parsed CA stack wrapped in `Arc<dyn Any>` for type-erased storage in `BackendTlsConfig`.
type ParsedCa = Arc<CaType>;

/// Holds the system CA stack loaded once at startup.
///
/// Used by all backend pools whose policy specifies `wellKnownCACertificates: System`.
pub struct UpstreamTls {
    system_ca: Arc<CaType>,
}

impl UpstreamTls {
    pub fn new(system_ca: Arc<CaType>) -> Self {
        Self { system_ca }
    }

    /// Returns the CA stack for `cfg`, parsing PEM on first use via `OnceLock`.
    pub fn ca_stack(&self, cfg: &Arc<BackendTlsConfig>) -> Arc<CaType> {
        let parsed: &Arc<dyn Any + Send + Sync> = cfg.parsed_or_init(|| {
            let stack: ParsedCa = match &cfg.ca_source {
                BackendCaSource::System => Arc::clone(&self.system_ca),
                BackendCaSource::Pem(pem) => {
                    let certs = X509::stack_from_pem(pem).unwrap_or_default();
                    Arc::new(certs.into_boxed_slice())
                }
            };
            stack as Arc<dyn Any + Send + Sync>
        });
        parsed
            .clone()
            .downcast::<CaType>()
            .expect("BackendTlsConfig parsed field is always CaType")
    }
}

/// Build the system CA stack from platform native roots.
///
/// Returns an empty stack (logging a warning) when native certs are unavailable
/// (e.g. sandboxed environments). Policies requesting `wellKnownCACertificates: System`
/// will then be marked `Accepted=False` by the controller.
pub fn load_system_ca() -> Arc<CaType> {
    let result = rustls_native_certs::load_native_certs();
    for err in &result.errors {
        tracing::warn!(error = %err, "Error loading a system CA certificate");
    }
    let stack: Vec<X509> = result
        .certs
        .into_iter()
        .filter_map(|der| X509::from_der(der.as_ref()).ok())
        .collect();
    if stack.is_empty() {
        tracing::warn!(
            "No system CA certificates loaded; BackendTLSPolicy wellKnownCACertificates: System will not verify backends"
        );
    } else {
        tracing::debug!(
            count = stack.len(),
            "Loaded system CA certificates for upstream TLS"
        );
    }
    Arc::new(stack.into_boxed_slice())
}
