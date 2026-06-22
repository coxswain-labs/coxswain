//! mTLS authentication for the discovery channel.
//!
//! Provides SPIFFE URI-SAN verification on both ends of the gRPC connection:
//! a custom [`rustls::client::danger::ServerCertVerifier`] for the proxy (client
//! side) and a custom [`rustls::server::danger::ClientCertVerifier`] for the
//! controller (server side).  Both verifiers:
//!
//! 1. Validate the certificate chain against the configured CA bundle using
//!    WebPKI trust anchors.
//! 2. Extract **only URI SANs** from the end-entity certificate (DNS SANs are
//!    never used for identity in SPIFFE/SVID).
//! 3. Match at least one URI SAN against the configured [`SpiffeMatcher`].
//!
//! A SAN mismatch or chain failure is a **hard TLS handshake error**: the proxy
//! stays `NotReady` and does not fall back to plaintext.
//!
//! ## Constructors
//!
//! - Server (controller) side: [`DiscoveryServerTls::acceptor`] →
//!   [`tokio_rustls::TlsAcceptor`].
//! - Client (proxy) side: [`DiscoveryClientTls::apply`] wraps a tonic
//!   [`tonic::transport::Endpoint`] with TLS.

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use tokio_rustls::TlsAcceptor;
use tonic::transport::{ClientTlsConfig, Endpoint, Identity};
use x509_parser::prelude::*;

use crate::error::AuthError;

// ── SPIFFE matcher ────────────────────────────────────────────────────────────

/// Pattern used to match a SPIFFE URI SAN against an expected identity.
///
/// SPIFFE IDs are URIs of the form `spiffe://<trust-domain>/path`.
///
/// - `Exact` is used for fixed peer identities, typically the controller:
///   `spiffe://cluster.local/ns/coxswain-system/sa/coxswain-controller`.
/// - `Prefix` is used for pools of peers where a common path prefix identifies
///   the role: `spiffe://cluster.local/ns/coxswain-system/sa/coxswain-proxy`
///   matches any SVID whose URI SAN starts with that string.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum SpiffeMatcher {
    /// The URI SAN must be exactly this string.
    Exact(String),
    /// The URI SAN must start with this prefix string.
    Prefix(String),
}

impl SpiffeMatcher {
    /// Returns `true` if `uri` satisfies this matcher.
    #[must_use]
    pub fn matches(&self, uri: &str) -> bool {
        match self {
            Self::Exact(s) => uri == s,
            Self::Prefix(p) => uri.starts_with(p.as_str()),
        }
    }
}

// ── URI SAN extraction ─────────────────────────────────────────────────────────

/// Extract all URI SANs from a DER-encoded end-entity certificate.
///
/// Only `GeneralName::URI` entries are returned; DNS, IP, and email SANs are
/// intentionally excluded so SPIFFE identity is never inferred from non-URI SANs.
///
/// # Errors
///
/// Returns [`AuthError::InvalidCert`] if the DER bytes cannot be parsed.
fn uri_sans(cert_der: &[u8]) -> Result<Vec<String>, AuthError> {
    let (_, cert) =
        parse_x509_certificate(cert_der).map_err(|e| AuthError::InvalidCert(e.to_string()))?;

    let Some(san_ext) = cert
        .subject_alternative_name()
        .map_err(|e| AuthError::InvalidCert(e.to_string()))?
    else {
        return Ok(Vec::new());
    };

    let uris = san_ext
        .value
        .general_names
        .iter()
        .filter_map(|name| {
            if let GeneralName::URI(uri) = name {
                Some((*uri).to_owned())
            } else {
                None
            }
        })
        .collect();

    Ok(uris)
}

// ── SpiffeServerCertVerifier ───────────────────────────────────────────────────

/// rustls client-side verifier: validates the controller's certificate.
///
/// Delegates chain and signature verification to an inner
/// [`WebPkiServerVerifier`] (which uses ring crypto), but replaces the
/// standard DNS-name check with a SPIFFE URI SAN match.  The `server_name`
/// argument from tonic is ignored; identity is established solely by the URI
/// SAN.
#[derive(Debug)]
pub(crate) struct SpiffeServerCertVerifier {
    /// Inner verifier used for signature delegation.
    inner: Arc<WebPkiServerVerifier>,
    /// Trust anchors for chain validation (same roots as inner).
    roots: Arc<RootCertStore>,
    /// Expected SPIFFE identity of the controller.
    matcher: SpiffeMatcher,
}

impl ServerCertVerifier for SpiffeServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // 1. Chain validation against our CA roots (no DNS-name check).
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &self.roots,
            intermediates,
            now,
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .all,
        )?;

        // 2. URI SAN identity check.
        let uris = uri_sans(end_entity.as_ref()).map_err(|_| {
            TlsError::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
        })?;
        if !uris.iter().any(|u| self.matcher.matches(u)) {
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ── SpiffeClientCertVerifier ───────────────────────────────────────────────────

/// rustls server-side verifier: validates the proxy's certificate.
///
/// Wraps a [`WebPkiClientVerifier`] that mandates client auth and performs
/// chain validation.  Adds a SPIFFE URI SAN match on top; a client that passes
/// chain validation but presents the wrong SPIFFE ID is rejected.
#[derive(Debug)]
pub(crate) struct SpiffeClientCertVerifier {
    /// Inner verifier returned by `WebPkiClientVerifier::builder().build()`.
    inner: Arc<dyn ClientCertVerifier>,
    matcher: SpiffeMatcher,
}

impl ClientCertVerifier for SpiffeClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        // 1. Chain + clientAuth EKU validation via WebPki.
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;

        // 2. URI SAN identity check.
        let uris = uri_sans(end_entity.as_ref()).map_err(|_| {
            TlsError::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
        })?;
        if !uris.iter().any(|u| self.matcher.matches(u)) {
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ── helpers ────────────────────────────────────────────────────────────────────

/// Build a [`RootCertStore`] from PEM-encoded CA certificate(s).
///
/// # Errors
///
/// Returns [`AuthError::InvalidPem`] if the PEM cannot be parsed or contains no
/// certificates.
fn build_root_cert_store(ca_pem: &[u8]) -> Result<RootCertStore, AuthError> {
    let mut roots = RootCertStore::empty();
    let mut count = 0usize;
    for cert_result in CertificateDer::pem_slice_iter(ca_pem) {
        let cert = cert_result.map_err(|e| AuthError::InvalidPem(e.to_string()))?;
        roots.add(cert).map_err(AuthError::Rustls)?;
        count += 1;
    }
    if count == 0 {
        return Err(AuthError::InvalidPem(
            "no certificates found in CA bundle".into(),
        ));
    }
    Ok(roots)
}

// ── DiscoveryServerTls ────────────────────────────────────────────────────────

/// TLS configuration for the discovery server (controller side).
///
/// Fields are PEM-encoded bytes so they can be loaded from files or Kubernetes
/// Secrets without an intermediate on-disk format.
// intentionally open: field-literal constructed at the bin layer
pub struct DiscoveryServerTls {
    /// PEM-encoded TLS certificate chain for the server.
    pub server_cert_pem: Vec<u8>,
    /// PEM-encoded private key matching `server_cert_pem`.
    pub server_key_pem: Vec<u8>,
    /// PEM-encoded CA certificate used to verify connecting proxy clients.
    pub client_ca_pem: Vec<u8>,
    /// SPIFFE identity pattern that proxy clients must satisfy.
    pub allowed_client: SpiffeMatcher,
}

impl DiscoveryServerTls {
    /// Build a [`TlsAcceptor`] that requires mTLS from every connecting client.
    ///
    /// The acceptor is configured with:
    /// - ALPN `h2` so tonic's HTTP/2 framing is negotiated correctly.
    /// - Client certificate mandatory (no anonymous connections).
    /// - SPIFFE URI SAN validation on the client certificate.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] if the certificate/key PEM cannot be parsed or the
    /// rustls configuration is invalid.
    #[must_use = "the TlsAcceptor must be used to wrap the TCP listener"]
    pub fn acceptor(&self) -> Result<TlsAcceptor, AuthError> {
        // Client verifier: require client cert + SPIFFE SAN check.
        let client_roots = Arc::new(build_root_cert_store(&self.client_ca_pem)?);
        let inner_client_verifier = WebPkiClientVerifier::builder(client_roots)
            .build()
            .map_err(|e| AuthError::VerifierBuild(e.to_string()))?;
        let client_verifier = Arc::new(SpiffeClientCertVerifier {
            inner: inner_client_verifier,
            matcher: self.allowed_client.clone(),
        });

        // Server certificate and key.
        let cert_chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(self.server_cert_pem.as_slice())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| AuthError::InvalidPem(e.to_string()))?;
        if cert_chain.is_empty() {
            return Err(AuthError::InvalidPem(
                "no certificates found in server cert PEM".into(),
            ));
        }
        let private_key = PrivateKeyDer::from_pem_slice(&self.server_key_pem)
            .map_err(|e| AuthError::InvalidPem(e.to_string()))?;

        // Build ServerConfig: mandatory client auth, ALPN h2.
        let mut server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(cert_chain, private_key)
            .map_err(AuthError::Rustls)?;
        server_config.alpn_protocols = vec![b"h2".to_vec()];

        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }
}

// ── DiscoveryClientTls ────────────────────────────────────────────────────────

/// TLS configuration for the discovery client (proxy side).
///
/// Fields are PEM-encoded bytes so they can be loaded from files or Kubernetes
/// Secrets without an intermediate on-disk format.
// intentionally open: field-literal constructed at the bin layer
pub struct DiscoveryClientTls {
    /// PEM-encoded mTLS client certificate chain presented to the server.
    pub client_cert_pem: Vec<u8>,
    /// PEM-encoded private key matching `client_cert_pem`.
    pub client_key_pem: Vec<u8>,
    /// PEM-encoded CA certificate used to verify the server (controller).
    pub server_ca_pem: Vec<u8>,
    /// Expected SPIFFE identity of the controller server.
    pub expected_server: SpiffeMatcher,
}

impl DiscoveryClientTls {
    /// Wrap `endpoint` with mTLS using this configuration.
    ///
    /// The resulting endpoint verifies the server's certificate chain against
    /// the configured CA roots **and** checks the server's SPIFFE URI SAN.
    /// The proxy's client identity is attached as `Identity::from_pem` so the
    /// controller can reciprocally verify the proxy's SPIFFE ID.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] if the certificate/key PEM cannot be parsed, the
    /// verifier cannot be built, or tonic rejects the TLS configuration.
    #[must_use = "the wrapped Endpoint must be used to open the channel"]
    pub fn apply(&self, endpoint: Endpoint) -> Result<Endpoint, AuthError> {
        // Build server-cert verifier from the controller CA roots.
        let server_roots = Arc::new(build_root_cert_store(&self.server_ca_pem)?);
        let inner_server_verifier = WebPkiServerVerifier::builder(server_roots.clone())
            .build()
            .map_err(|e| AuthError::VerifierBuild(e.to_string()))?;
        let server_verifier = Arc::new(SpiffeServerCertVerifier {
            inner: inner_server_verifier,
            roots: server_roots,
            matcher: self.expected_server.clone(),
        });

        let identity = Identity::from_pem(&self.client_cert_pem, &self.client_key_pem);
        let tls_config = ClientTlsConfig::new().identity(identity);

        endpoint
            .tls_config_with_verifier(tls_config, server_verifier)
            .map_err(|e| AuthError::VerifierBuild(e.to_string()))
    }
}

// ── DiscoveryBootstrapServerTls ───────────────────────────────────────────────

/// TLS configuration for the bootstrap listener (server-auth-only).
///
/// The bootstrap endpoint uses server-authentication-only TLS — the proxy does
/// **not** present a client certificate (it has none yet; that's exactly why it
/// is bootstrapping).  Instead, the proxy verifies the controller's server cert
/// against the CA bundle it mounted from the trust-bundle ConfigMap before
/// calling Bootstrap.
///
/// This is intentionally distinct from [`DiscoveryServerTls`], which builds a
/// `ServerConfig` that mandates client certs.  Mixing optional-and-mandatory
/// client auth on one `ServerConfig` is fragile and would weaken the hard-fail
/// SAN guarantee on the mTLS `Stream` port.
// intentionally open: field-literal constructed at the bin layer
pub struct DiscoveryBootstrapServerTls {
    /// PEM-encoded TLS certificate chain for the server (typically a controller SVID).
    pub server_cert_pem: Vec<u8>,
    /// PEM-encoded private key matching `server_cert_pem`.
    pub server_key_pem: Vec<u8>,
}

impl DiscoveryBootstrapServerTls {
    /// Build a [`TlsAcceptor`] with server-auth-only TLS (no client cert required).
    ///
    /// The acceptor is configured with:
    /// - ALPN `h2` for tonic's HTTP/2 framing.
    /// - No client certificate requested or verified.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] if the certificate/key PEM cannot be parsed or the
    /// rustls configuration is invalid.
    #[must_use = "the TlsAcceptor must be used to wrap the TCP listener"]
    pub fn acceptor(&self) -> Result<TlsAcceptor, AuthError> {
        let cert_chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(self.server_cert_pem.as_slice())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| AuthError::InvalidPem(e.to_string()))?;
        if cert_chain.is_empty() {
            return Err(AuthError::InvalidPem(
                "no certificates found in bootstrap server cert PEM".into(),
            ));
        }
        let private_key = PrivateKeyDer::from_pem_slice(&self.server_key_pem)
            .map_err(|e| AuthError::InvalidPem(e.to_string()))?;

        // Server-auth-only: no client cert required.
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(AuthError::Rustls)?;
        server_config.alpn_protocols = vec![b"h2".to_vec()];

        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }
}

// ── DiscoveryBootstrapClientTls ───────────────────────────────────────────────

/// TLS configuration for the bootstrap gRPC client (proxy side, server-auth-only).
///
/// The proxy verifies the controller's server certificate against the CA bundle
/// from the trust-bundle ConfigMap mount.  No client certificate is presented —
/// the proxy has no SVID yet; that is the whole point of bootstrapping.
///
/// Distinct from [`DiscoveryClientTls`] (which requires a client cert for mTLS).
// intentionally open: field-literal constructed in bootstrap_client
pub struct DiscoveryBootstrapClientTls {
    /// PEM-encoded CA bundle from the trust-bundle ConfigMap.
    pub server_ca_pem: Vec<u8>,
    /// Expected SPIFFE identity of the controller bootstrap server.
    pub expected_server: SpiffeMatcher,
}

impl DiscoveryBootstrapClientTls {
    /// Wrap `endpoint` with server-auth-only TLS.
    ///
    /// The resulting endpoint verifies the server's SPIFFE URI SAN against
    /// `expected_server` but does **not** present a client certificate.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] if the CA bundle PEM cannot be parsed or the
    /// verifier cannot be built.
    #[must_use = "the wrapped Endpoint must be used to open the channel"]
    pub fn apply(&self, endpoint: Endpoint) -> Result<Endpoint, AuthError> {
        let server_roots = Arc::new(build_root_cert_store(&self.server_ca_pem)?);
        let inner_server_verifier = WebPkiServerVerifier::builder(server_roots.clone())
            .build()
            .map_err(|e| AuthError::VerifierBuild(e.to_string()))?;
        let server_verifier = Arc::new(SpiffeServerCertVerifier {
            inner: inner_server_verifier,
            roots: server_roots,
            matcher: self.expected_server.clone(),
        });

        // No identity — server-auth-only.
        let tls_config = ClientTlsConfig::new();
        endpoint
            .tls_config_with_verifier(tls_config, server_verifier)
            .map_err(|e| AuthError::VerifierBuild(e.to_string()))
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose, SanType,
    };
    use tokio::net::TcpListener;
    use tokio_stream::StreamExt;
    use tonic::transport::{Endpoint, Server};
    use tonic::{Request, Response, Status, Streaming};

    use crate::proto::v1::discovery_server::{Discovery, DiscoveryServer};
    use crate::proto::v1::{
        self as p, ClientMessage, ServerMessage, client_message::Kind as CKind,
        server_message::Kind as SrvKind,
    };
    use crate::version::WIRE_VERSION;

    // ── rcgen helpers ─────────────────────────────────────────────────────────

    /// A CA + two leaf certs (server + client) all with SPIFFE URI SANs.
    pub(crate) struct SpiffeTestCerts {
        pub ca_cert_pem: Vec<u8>,
        pub server_cert_pem: Vec<u8>,
        pub server_key_pem: Vec<u8>,
        pub client_cert_pem: Vec<u8>,
        pub client_key_pem: Vec<u8>,
    }

    const CONTROLLER_SPIFFE: &str =
        "spiffe://cluster.local/ns/coxswain-system/sa/coxswain-controller";
    const PROXY_SPIFFE: &str = "spiffe://cluster.local/ns/coxswain-system/sa/coxswain-proxy";

    fn gen_ca() -> (rcgen::Certificate, KeyPair, CertificateParams) {
        let mut params =
            CertificateParams::new(vec![]).unwrap_or_else(|e| panic!("rcgen CA params: {e}"));
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let key = KeyPair::generate().unwrap_or_else(|e| panic!("rcgen CA key: {e}"));
        let cert = params
            .self_signed(&key)
            .unwrap_or_else(|e| panic!("rcgen CA self-sign: {e}"));
        (cert, key, params)
    }

    fn gen_leaf(spiffe_uri: &str, issuer: &Issuer<KeyPair>) -> (rcgen::Certificate, KeyPair) {
        let uri_san: SanType = SanType::URI(
            spiffe_uri
                .try_into()
                .unwrap_or_else(|e| panic!("rcgen SanType::URI for {spiffe_uri}: {e}")),
        );
        let mut params =
            CertificateParams::new(vec![]).unwrap_or_else(|e| panic!("rcgen leaf params: {e}"));
        params.subject_alt_names = vec![uri_san];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = KeyPair::generate().unwrap_or_else(|e| panic!("rcgen leaf key: {e}"));
        let cert = params
            .signed_by(&key, issuer)
            .unwrap_or_else(|e| panic!("rcgen leaf sign: {e}"));
        (cert, key)
    }

    /// Generate a fresh CA + controller SVID + proxy SVID set.
    pub(crate) fn gen_certs() -> SpiffeTestCerts {
        let (ca_cert, ca_key, ca_params) = gen_ca();
        let issuer = Issuer::new(ca_params, ca_key);

        let (server_cert, server_key) = gen_leaf(CONTROLLER_SPIFFE, &issuer);
        let (client_cert, client_key) = gen_leaf(PROXY_SPIFFE, &issuer);

        SpiffeTestCerts {
            ca_cert_pem: ca_cert.pem().into_bytes(),
            server_cert_pem: server_cert.pem().into_bytes(),
            server_key_pem: server_key.serialize_pem().into_bytes(),
            client_cert_pem: client_cert.pem().into_bytes(),
            client_key_pem: client_key.serialize_pem().into_bytes(),
        }
    }

    // ── minimal no-op Discovery impl for TLS tests ────────────────────────────

    struct NoOpDiscovery;

    #[async_trait::async_trait]
    impl Discovery for NoOpDiscovery {
        type StreamStream = tokio_stream::wrappers::ReceiverStream<Result<ServerMessage, Status>>;

        async fn bootstrap(
            &self,
            _req: tonic::Request<p::BootstrapRequest>,
        ) -> Result<tonic::Response<p::BootstrapResponse>, Status> {
            Err(Status::unimplemented("test stub"))
        }

        async fn stream(
            &self,
            request: Request<Streaming<ClientMessage>>,
        ) -> Result<Response<Self::StreamStream>, Status> {
            let mut inbound = request.into_inner();
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            // Drain Subscribe and send one empty snapshot so the client confirms open.
            tokio::spawn(async move {
                if let Ok(Some(_)) = inbound.message().await {
                    let snap = p::ServerMessage {
                        kind: Some(SrvKind::Snapshot(p::Snapshot {
                            version: "test-v1".into(),
                            nonce: vec![1],
                            ingress_routing: None,
                            gateway_routing: None,
                            tls_store: None,
                            client_cert_store: None,
                            listener_health: None,
                        })),
                    };
                    let _ = tx.send(Ok(snap)).await;
                }
            });
            Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
                rx,
            )))
        }
    }

    /// Start a TLS tonic server; returns its address and the TlsAcceptor used.
    async fn start_tls_server(server_tls: &DiscoveryServerTls) -> std::net::SocketAddr {
        let acceptor = server_tls
            .acceptor()
            .unwrap_or_else(|e| panic!("server TLS config: {e}"));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap();

        let incoming = {
            let acceptor = acceptor.clone();
            tokio_stream::wrappers::TcpListenerStream::new(listener).then(move |r| {
                let acceptor = acceptor.clone();
                async move {
                    let stream = r.map_err(|e| std::io::Error::other(e.to_string()))?;
                    acceptor
                        .accept(stream)
                        .await
                        .map_err(|e| std::io::Error::other(e.to_string()))
                }
            })
        };

        tokio::spawn(
            Server::builder()
                .add_service(DiscoveryServer::new(NoOpDiscovery))
                .serve_with_incoming(incoming),
        );

        addr
    }

    /// Open a discovery stream over TLS from a client.  Returns `Ok(true)` if
    /// the stream opened and a Snapshot arrived, `Err(status)` on failure.
    async fn try_open_tls_stream(
        addr: std::net::SocketAddr,
        client_tls: &DiscoveryClientTls,
    ) -> Result<bool, tonic::Status> {
        use crate::proto::v1::discovery_client::DiscoveryClient as TonicClient;

        let ep = Endpoint::from_shared(format!("https://{addr}")).expect("valid https URI");
        let ep = client_tls
            .apply(ep)
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        let channel = ep.connect_lazy();
        let mut grpc = TonicClient::new(channel);

        let (tx, rx) = tokio::sync::mpsc::channel::<ClientMessage>(4);
        tx.send(ClientMessage {
            kind: Some(CKind::Subscribe(p::Subscribe {
                node_id: "test-proxy".into(),
                wire_version: WIRE_VERSION,
                scope: Some(p::Scope {}),
            })),
        })
        .await
        .expect("pre-queue subscribe");

        let response = grpc
            .stream(tokio_stream::wrappers::ReceiverStream::new(rx))
            .await?;
        let mut inbound = response.into_inner();

        let got_snapshot =
            tokio::time::timeout(std::time::Duration::from_secs(3), inbound.message())
                .await
                .map_err(|_| tonic::Status::deadline_exceeded("timed out"))?
                .map_err(|e| e)?
                .is_some();

        Ok(got_snapshot)
    }

    // ── unit tests ────────────────────────────────────────────────────────────

    /// URI SANs are extracted; DNS SANs are ignored.
    #[test]
    fn uri_san_extracted_not_dns() {
        // Generate a cert that has both a URI SAN and a DNS SAN.
        let (ca_cert, ca_key, ca_params) = gen_ca();
        let issuer = Issuer::new(ca_params, ca_key);
        let uri_san: SanType = SanType::URI(
            CONTROLLER_SPIFFE
                .try_into()
                .expect("valid URI SAN for test cert"),
        );
        let dns_san: SanType = SanType::DnsName(
            "example.com"
                .try_into()
                .expect("valid DNS SAN for test cert"),
        );
        let mut params =
            CertificateParams::new(vec![]).expect("rcgen leaf params for uri_san test");
        params.subject_alt_names = vec![uri_san, dns_san];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().expect("rcgen leaf key for uri_san test");
        let cert = params
            .signed_by(&key, &issuer)
            .expect("rcgen leaf sign for uri_san test");

        let cert_der: CertificateDer<'static> =
            CertificateDer::from_pem_slice(cert.pem().as_bytes())
                .expect("parse test cert DER from PEM");

        let _ = ca_cert; // keep CA alive until after signing

        let uris = uri_sans(cert_der.as_ref()).expect("uri_sans extraction");
        assert_eq!(uris, vec![CONTROLLER_SPIFFE.to_owned()]);
    }

    /// Exact matcher accepts only identical URIs; prefix matcher accepts anything starting with it.
    #[test]
    fn spiffe_matcher_exact_and_prefix() {
        let exact = SpiffeMatcher::Exact(CONTROLLER_SPIFFE.into());
        assert!(exact.matches(CONTROLLER_SPIFFE));
        assert!(!exact.matches(PROXY_SPIFFE));
        assert!(
            !exact.matches("spiffe://other.example.com/ns/coxswain-system/sa/coxswain-controller")
        );

        let prefix = SpiffeMatcher::Prefix(
            "spiffe://cluster.local/ns/coxswain-system/sa/coxswain-proxy".into(),
        );
        assert!(prefix.matches(PROXY_SPIFFE));
        assert!(prefix.matches("spiffe://cluster.local/ns/coxswain-system/sa/coxswain-proxy-abc"));
        assert!(!prefix.matches(CONTROLLER_SPIFFE));
    }

    // ── integration tests (real TLS handshake over localhost) ─────────────────

    /// Both sides present valid SPIFFE SVIDs signed by the shared CA →
    /// handshake succeeds and the stream opens.
    #[tokio::test]
    async fn correct_san_both_sides_stream_established() {
        let certs = gen_certs();

        let server_tls = DiscoveryServerTls {
            server_cert_pem: certs.server_cert_pem.clone(),
            server_key_pem: certs.server_key_pem.clone(),
            client_ca_pem: certs.ca_cert_pem.clone(),
            allowed_client: SpiffeMatcher::Prefix(PROXY_SPIFFE.into()),
        };
        let client_tls = DiscoveryClientTls {
            client_cert_pem: certs.client_cert_pem.clone(),
            client_key_pem: certs.client_key_pem.clone(),
            server_ca_pem: certs.ca_cert_pem.clone(),
            expected_server: SpiffeMatcher::Exact(CONTROLLER_SPIFFE.into()),
        };

        let addr = start_tls_server(&server_tls).await;
        let result = try_open_tls_stream(addr, &client_tls).await;
        assert!(
            result.is_ok(),
            "stream should open when both sides have valid certs: {result:?}"
        );
    }

    /// Client presents a cert with a wrong URI SAN → server rejects at handshake.
    #[tokio::test]
    async fn bad_client_san_handshake_rejected() {
        let certs = gen_certs();

        // Generate a client cert with a mismatched SPIFFE ID.
        let (ca_cert_wrong, ca_key_wrong, ca_params_wrong) = gen_ca();
        let issuer_wrong = Issuer::new(ca_params_wrong, ca_key_wrong);
        let (bad_client_cert, bad_client_key) = gen_leaf(
            "spiffe://attacker.example.com/ns/evil/sa/evil",
            &issuer_wrong,
        );
        let _ = ca_cert_wrong;

        let server_tls = DiscoveryServerTls {
            server_cert_pem: certs.server_cert_pem.clone(),
            server_key_pem: certs.server_key_pem.clone(),
            client_ca_pem: certs.ca_cert_pem.clone(), // trusts coxswain CA, not attacker CA
            allowed_client: SpiffeMatcher::Prefix(PROXY_SPIFFE.into()),
        };
        let client_tls = DiscoveryClientTls {
            client_cert_pem: bad_client_cert.pem().into_bytes(),
            client_key_pem: bad_client_key.serialize_pem().into_bytes(),
            server_ca_pem: certs.ca_cert_pem.clone(),
            expected_server: SpiffeMatcher::Exact(CONTROLLER_SPIFFE.into()),
        };

        let addr = start_tls_server(&server_tls).await;
        let result = try_open_tls_stream(addr, &client_tls).await;
        assert!(
            result.is_err(),
            "stream must be rejected when client cert is not signed by the trusted CA"
        );
    }

    /// Server presents a cert with the wrong URI SAN (MITM) →
    /// client rejects at handshake; stream never established.
    #[tokio::test]
    async fn bad_server_san_client_rejects() {
        let certs = gen_certs();

        // Generate a server cert with a wrong SPIFFE ID.
        let (ca_cert, ca_key, ca_params) = gen_ca();
        let issuer = Issuer::new(ca_params, ca_key);
        let (bad_server_cert, bad_server_key) =
            gen_leaf("spiffe://attacker.example.com/ns/evil/sa/mitm", &issuer);
        let bad_ca = ca_cert;

        let server_tls = DiscoveryServerTls {
            server_cert_pem: bad_server_cert.pem().into_bytes(),
            server_key_pem: bad_server_key.serialize_pem().into_bytes(),
            client_ca_pem: certs.ca_cert_pem.clone(),
            allowed_client: SpiffeMatcher::Prefix(PROXY_SPIFFE.into()),
        };
        // Client trusts the attacker CA (so chain validates) but expects controller SPIFFE ID.
        let client_tls = DiscoveryClientTls {
            client_cert_pem: certs.client_cert_pem.clone(),
            client_key_pem: certs.client_key_pem.clone(),
            server_ca_pem: bad_ca.pem().into_bytes(),
            expected_server: SpiffeMatcher::Exact(CONTROLLER_SPIFFE.into()),
        };

        let addr = start_tls_server(&server_tls).await;
        let result = try_open_tls_stream(addr, &client_tls).await;
        assert!(
            result.is_err(),
            "stream must be rejected when server SPIFFE ID does not match expected: {result:?}"
        );
    }
}
