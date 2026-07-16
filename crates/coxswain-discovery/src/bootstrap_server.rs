//! Bootstrap gRPC service: issues SVIDs to fresh proxy nodes.
//!
//! [`BootstrapService`] implements the `Discovery::Bootstrap` RPC on its own
//! listener (server-auth-only TLS, port 50052).  A proxy that has no SVID yet
//! sends its projected ServiceAccount token and a CSR; the service validates the
//! token via [`TokenAuthenticator`], signs the CSR via [`SvidIssuer`], and
//! returns a short-lived SVID plus the current trust bundle.
//!
//! The design is deliberately generic over both interfaces so the controller
//! can inject concrete implementations (`KubeTokenAuthenticator`, `CertAuthority`)
//! without this crate depending on `coxswain-controller`.
//!
//! # Reject hook
//!
//! Bootstrap emits a reject hook (`RejectHook`) on every authentication failure.
//! The bin layer wires this to the controller's event recorder so a
//! `BootstrapRejected` Warning Event appears in the cluster — the controller is
//! the sole diagnostic emitter per crate charter.
//!
//! # Wiring
//!
//! `coxswain-bin` runs `BootstrapService` on a separate tonic server from
//! `DiscoveryService`:
//! - Port 50051: `DiscoveryServer::new(DiscoveryService)` — mTLS mandatory.
//! - Port 50052: `DiscoveryServer::new(BootstrapService)` — server-auth-only.

use std::collections::HashSet;
use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{info, warn};

use coxswain_core::Shared;
use coxswain_core::identity::{
    AuthnError, CsrPem, IssuerError, SpiffeId, SvidIssuer, TokenAuthenticator,
};

use crate::proto::v1::{
    BootstrapRequest, BootstrapResponse, ClientMessage, ServerMessage, discovery_server::Discovery,
};
use crate::subscription::Scope;
use crate::version::WIRE_VERSION;
use crate::wire::scope_from_wire;

// ── UpstreamResolverConfig ──────────────────────────────────────────────────────

/// Inputs the controller injects so the bootstrap handler can resolve each
/// client's best routing upstream at bootstrap time (#601).
///
/// Kept as plain data (no controller dependency): `coxswain-controller` depends
/// on this crate, not the reverse, so the endpoint templates and relay/controller
/// ServiceAccount names are passed in from `coxswain-bin`, which knows both sides.
/// The `active_relays` set is the controller's **repoint** set — namespaces whose
/// relay is Ready and serving (`RelayNsState::Active`), the make-before-break gate
/// that a leaf may repoint onto the relay. It is distinct from the authz set the
/// `ScopeAuthorizer` reads (which also covers provisioning/draining relays): a leaf
/// must never point at a not-yet-Ready or already-draining relay (#602).
// intentionally open: field-literal constructed in coxswain-bin
pub struct UpstreamResolverConfig {
    /// The controller's own routing (Stream) endpoint — the always-up fallback.
    pub controller_endpoint: String,
    /// The controller's ServiceAccount short-name (expected in its SVID).
    pub controller_sa: String,
    /// The shared relay's routing endpoint, when a shared relay fronts the pool
    /// (a static Helm toggle in v0.6). `None` = shared proxies stream from the
    /// controller.
    pub shared_relay_endpoint: Option<String>,
    /// The dedicated relay's Service name (e.g. `coxswain-relay`); the per-namespace
    /// endpoint is `https://{relay_service_name}.{namespace}.svc:{relay_port}`.
    pub relay_service_name: String,
    /// The dedicated relay's routing (Stream) port.
    pub relay_port: u16,
    /// The relay ServiceAccount short-name (expected in a relay's SVID, and the
    /// discriminator for the relays-never-tier rule).
    pub relay_sa: String,
    /// Namespaces whose dedicated relay is Ready and serving (the controller's
    /// repoint set): a dedicated leaf in one of these streams from the relay, else
    /// from the controller (#601/#602).
    pub active_relays: Shared<HashSet<String>>,
}

impl UpstreamResolverConfig {
    /// Resolve `(endpoint, expected_server_sa)` for a client with the given
    /// authenticated identity and subscription scope (#601).
    ///
    /// Rules, in order:
    /// - A **relay** (its SA matches `relay_sa`) always streams from the
    ///   controller — relays never tier.
    /// - A **shared-pool** client streams from the shared relay if one is
    ///   configured, else the controller.
    /// - A **dedicated** (Gateway/Namespace) client streams from its namespace's
    ///   relay if that namespace is provisioned, else the controller.
    #[must_use]
    pub fn resolve(&self, spiffe: &SpiffeId, scope: &Scope) -> (String, String) {
        if spiffe.service_account() == self.relay_sa {
            return self.controller_target();
        }
        match scope {
            Scope::SharedPool => match &self.shared_relay_endpoint {
                Some(endpoint) => (endpoint.clone(), self.relay_sa.clone()),
                None => self.controller_target(),
            },
            Scope::Gateway { namespace, .. } | Scope::Namespace { namespace } => {
                self.resolve_namespace(namespace)
            }
        }
    }

    /// Resolve `(endpoint, expected_server_sa)` for a dedicated (namespace-scoped)
    /// client: its namespace's relay if that relay is **Active** (Ready and
    /// serving), else the controller (#601/#602).
    ///
    /// Used by the controller's stream server to compute a leaf's current best
    /// upstream when deciding whether to push a live repoint directive. Reads the
    /// repoint set ([`Self::active_relays`]), not the authz set, so a leaf is never
    /// pointed at a still-provisioning or draining relay. Unlike [`Self::resolve`]
    /// it takes no identity — the stream push only ever targets dedicated leaves,
    /// never a relay (the relays-never-tier rule is enforced at bootstrap, where the
    /// SA is authenticated).
    #[must_use]
    pub fn resolve_namespace(&self, namespace: &str) -> (String, String) {
        if self.active_relays.load().contains(namespace) {
            let endpoint = format!(
                "https://{}.{}.svc:{}",
                self.relay_service_name, namespace, self.relay_port
            );
            (endpoint, self.relay_sa.clone())
        } else {
            self.controller_target()
        }
    }

    /// The controller's own `(endpoint, sa)` — the always-up fallback anchor, and
    /// the upstream every Gateway-scope client connected directly to the
    /// controller is currently streaming from (#601 seed baseline).
    #[must_use]
    pub fn controller_target(&self) -> (String, String) {
        (self.controller_endpoint.clone(), self.controller_sa.clone())
    }
}

// ── RejectHook ────────────────────────────────────────────────────────────────

/// Callback invoked when a Bootstrap request is rejected.
///
/// The controller wires this to its event recorder to emit a `BootstrapRejected`
/// Warning Event.  The discovery crate itself never touches the Kubernetes API.
pub trait RejectHook: Send + Sync {
    /// Called when a bootstrap request is rejected.  `principal` is the SA
    /// identity string extracted from the token (if authentication succeeded
    /// but something else failed), or the raw error context otherwise.
    ///
    /// Awaited inline by the bootstrap handler: the controller's implementation
    /// publishes a Kubernetes Event, and that publish must run (and surface its
    /// failures) on the handler's own task. A detached `tokio::spawn` is unsafe
    /// here — the discovery server runs as a Pingora background service whose
    /// runtime does not reliably drive orphaned tasks, so a fire-and-forget
    /// publish can silently never execute.
    fn on_reject(
        &self,
        principal: &str,
        reason: &str,
    ) -> impl std::future::Future<Output = ()> + Send;
}

/// No-op reject hook used as the default when no event recorder is available.
// intentionally open: constructed as a unit struct literal `NoOpRejectHook` by callers
pub struct NoOpRejectHook;

impl RejectHook for NoOpRejectHook {
    async fn on_reject(&self, _principal: &str, _reason: &str) {}
}

// ── BootstrapService ──────────────────────────────────────────────────────────

/// Discovery service implementation that handles the Bootstrap RPC only.
///
/// - `I` — signs CSRs and provides the trust bundle; implements [`SvidIssuer`].
/// - `A` — validates SA tokens; implements [`TokenAuthenticator`].
/// - `H` — called on rejection; implements [`RejectHook`].
///
/// Serve this on a *separate* tonic listener with server-auth-only TLS.
/// The `Stream` RPC always returns `Unimplemented`; proxy clients must
/// connect to the Stream listener (port 50051) for routing snapshots.
#[non_exhaustive]
pub struct BootstrapService<I, A, H = NoOpRejectHook> {
    issuer: Arc<I>,
    authenticator: Arc<A>,
    reject_hook: Arc<H>,
    /// Best-upstream resolver (#601). `None` in tests / plaintext paths, in which
    /// case the response carries an empty upstream pointer (the client keeps its
    /// configured fallback).
    upstream: Option<Arc<UpstreamResolverConfig>>,
}

impl<I, A> BootstrapService<I, A, NoOpRejectHook>
where
    I: SvidIssuer,
    A: TokenAuthenticator,
{
    /// Create a `BootstrapService` with the default no-op reject hook.
    #[must_use]
    pub fn new(issuer: Arc<I>, authenticator: Arc<A>) -> Self {
        Self {
            issuer,
            authenticator,
            reject_hook: Arc::new(NoOpRejectHook),
            upstream: None,
        }
    }
}

impl<I, A, H> BootstrapService<I, A, H>
where
    I: SvidIssuer,
    A: TokenAuthenticator,
    H: RejectHook,
{
    /// Create a `BootstrapService` with a custom reject hook.
    #[must_use]
    pub fn with_reject_hook(issuer: Arc<I>, authenticator: Arc<A>, reject_hook: Arc<H>) -> Self {
        Self {
            issuer,
            authenticator,
            reject_hook,
            upstream: None,
        }
    }

    /// Attach the best-upstream resolver (#601) so bootstrap responses carry the
    /// client's current best routing upstream `(endpoint, expected_server_sa)`.
    #[must_use]
    pub fn with_upstream_resolver(mut self, resolver: Arc<UpstreamResolverConfig>) -> Self {
        self.upstream = Some(resolver);
        self
    }
}

#[async_trait::async_trait]
impl<I, A, H> Discovery for BootstrapService<I, A, H>
where
    I: SvidIssuer + 'static,
    A: TokenAuthenticator + 'static,
    H: RejectHook + 'static,
{
    type StreamStream = tokio_stream::wrappers::ReceiverStream<Result<ServerMessage, Status>>;

    /// Stream RPC: not served on the bootstrap listener.
    ///
    /// Returns `Unimplemented` so proxies that accidentally hit the wrong port
    /// get a clear error rather than a hang.
    async fn stream(
        &self,
        _request: Request<tonic::Streaming<ClientMessage>>,
    ) -> Result<Response<Self::StreamStream>, Status> {
        Err(Status::unimplemented(
            "Stream RPC is served on the discovery port (50051), not the bootstrap port (50052)",
        ))
    }

    /// Bootstrap RPC: validate SA token, sign CSR, return SVID + trust bundle.
    ///
    /// # Flow
    ///
    /// 1. Reject requests with a mismatched `wire_version` (clear protocol error).
    /// 2. Authenticate the SA token via [`TokenAuthenticator`] → [`SpiffeId`].
    /// 3. Sign the CSR via [`SvidIssuer`] → [`coxswain_core::identity::IssuedSvid`].
    /// 4. Return the cert PEM, trust bundle PEM, and `not_after` timestamp.
    ///
    /// Any failure invokes the reject hook before returning `Unauthenticated`.
    async fn bootstrap(
        &self,
        request: Request<BootstrapRequest>,
    ) -> Result<Response<BootstrapResponse>, Status> {
        let req = request.into_inner();

        // 1. Wire-version check.
        if req.wire_version != WIRE_VERSION {
            let reason = format!(
                "wire version mismatch: server={WIRE_VERSION}, client={}",
                req.wire_version
            );
            reject("wire_version");
            self.reject_hook.on_reject("<unknown>", &reason).await;
            return Err(Status::failed_precondition(reason));
        }

        // 2. Authenticate the SA token.
        let spiffe_id: SpiffeId = match self.authenticator.authenticate(&req.sa_token).await {
            Ok(id) => id,
            Err(AuthnError::Unauthenticated(msg)) => {
                warn!(reason = %msg, "bootstrap: SA token rejected");
                reject("sa_token");
                self.reject_hook.on_reject("<unauthenticated>", &msg).await;
                return Err(Status::unauthenticated(format!("SA token rejected: {msg}")));
            }
            Err(AuthnError::ApiError(msg)) => {
                warn!(reason = %msg, "bootstrap: TokenReview API error");
                reject("token_review_error");
                self.reject_hook.on_reject("<api-error>", &msg).await;
                return Err(Status::internal(format!("TokenReview error: {msg}")));
            }
            Err(AuthnError::InvalidPrincipal(msg)) => {
                warn!(reason = %msg, "bootstrap: unexpected principal format");
                reject("invalid_principal");
                self.reject_hook
                    .on_reject("<invalid-principal>", &msg)
                    .await;
                return Err(Status::unauthenticated(format!(
                    "unexpected principal: {msg}"
                )));
            }
            // AuthnError is #[non_exhaustive]; treat unknown variants as internal errors.
            Err(e) => {
                let msg = e.to_string();
                warn!(reason = %msg, "bootstrap: unexpected auth error");
                reject("internal");
                self.reject_hook.on_reject("<unknown>", &msg).await;
                return Err(Status::internal(format!("authentication error: {msg}")));
            }
        };

        info!(spiffe_id = %spiffe_id, "bootstrap: SA token authenticated");

        // 3. Sign the CSR.
        let csr = CsrPem::new(req.csr_pem);
        let svid = match self.issuer.sign_csr(&csr, &spiffe_id) {
            Ok(s) => s,
            Err(IssuerError::NotReady) => {
                let msg = "CA not yet initialised";
                reject("ca_not_ready");
                self.reject_hook.on_reject(spiffe_id.as_str(), msg).await;
                return Err(Status::unavailable(msg));
            }
            Err(IssuerError::MalformedCsr(msg)) => {
                warn!(spiffe_id = %spiffe_id, reason = %msg, "bootstrap: malformed CSR");
                reject("malformed_csr");
                self.reject_hook.on_reject(spiffe_id.as_str(), &msg).await;
                return Err(Status::invalid_argument(format!("malformed CSR: {msg}")));
            }
            Err(IssuerError::Signing(msg)) => {
                warn!(spiffe_id = %spiffe_id, reason = %msg, "bootstrap: signing error");
                reject("signing_error");
                self.reject_hook.on_reject(spiffe_id.as_str(), &msg).await;
                return Err(Status::internal(format!("signing error: {msg}")));
            }
            // IssuerError is #[non_exhaustive]; treat unknown variants as internal errors.
            Err(e) => {
                let msg = e.to_string();
                warn!(spiffe_id = %spiffe_id, reason = %msg, "bootstrap: unexpected issuer error");
                reject("internal");
                self.reject_hook.on_reject(spiffe_id.as_str(), &msg).await;
                return Err(Status::internal(format!("issuer error: {msg}")));
            }
        };

        // Accept: one signed SVID returned to the proxy.
        crate::metrics::bootstrap_total()
            .with_label_values(&["accepted", "ok"])
            .inc();
        crate::metrics::svid_issued_total().inc();

        let trust_bundle = self.issuer.trust_bundle();

        // Resolve the client's best routing upstream (#601). An absent resolver
        // (tests/plaintext) or an unparseable scope degrades to an empty pointer,
        // so the client keeps its configured fallback rather than being dialled
        // at a bogus endpoint.
        let (upstream_endpoint, expected_server_sa) = match &self.upstream {
            Some(resolver) => {
                let scope = req
                    .scope
                    .as_ref()
                    .and_then(|dto| scope_from_wire(dto).ok())
                    .unwrap_or(Scope::SharedPool);
                resolver.resolve(&spiffe_id, &scope)
            }
            None => (String::new(), String::new()),
        };

        info!(
            spiffe_id = %spiffe_id,
            not_after = svid.not_after_unix,
            upstream = %upstream_endpoint,
            "bootstrap: SVID issued"
        );

        Ok(Response::new(BootstrapResponse {
            svid_cert_pem: svid.cert_pem,
            trust_bundle_pem: trust_bundle,
            not_after_unix: svid.not_after_unix,
            upstream_endpoint,
            expected_server_sa,
        }))
    }
}

/// Record a rejected Bootstrap outcome on `coxswain_discovery_bootstrap_total`.
///
/// `reason` is the bounded discriminator (e.g. `sa_token`, `ca_not_ready`); the
/// `result` label is always `rejected` here — accepts are recorded inline in the
/// success path.
fn reject(reason: &str) {
    crate::metrics::bootstrap_total()
        .with_label_values(&["rejected", reason])
        .inc();
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use coxswain_core::identity::{AuthnError, IssuedSvid, IssuerError};

    // ── stub impls ────────────────────────────────────────────────────────────

    struct OkIssuer {
        cert: Vec<u8>,
        bundle: Vec<u8>,
        not_after: i64,
    }

    impl SvidIssuer for OkIssuer {
        fn sign_csr(&self, _csr: &CsrPem, _id: &SpiffeId) -> Result<IssuedSvid, IssuerError> {
            Ok(IssuedSvid {
                cert_pem: self.cert.clone(),
                not_after_unix: self.not_after,
            })
        }
        fn trust_bundle(&self) -> Vec<u8> {
            self.bundle.clone()
        }
    }

    struct FailIssuer(IssuerError);

    impl SvidIssuer for FailIssuer {
        fn sign_csr(&self, _csr: &CsrPem, _id: &SpiffeId) -> Result<IssuedSvid, IssuerError> {
            Err(match &self.0 {
                IssuerError::NotReady => IssuerError::NotReady,
                IssuerError::MalformedCsr(m) => IssuerError::MalformedCsr(m.clone()),
                IssuerError::Signing(m) => IssuerError::Signing(m.clone()),
                // #[non_exhaustive]: propagate any future variants as a Signing error.
                _ => IssuerError::Signing("unexpected variant in test".into()),
            })
        }
        fn trust_bundle(&self) -> Vec<u8> {
            vec![]
        }
    }

    struct OkAuthenticator(SpiffeId);

    impl TokenAuthenticator for OkAuthenticator {
        async fn authenticate(&self, _token: &str) -> Result<SpiffeId, AuthnError> {
            Ok(self.0.clone())
        }
    }

    struct RejectAuthenticator(String);

    impl TokenAuthenticator for RejectAuthenticator {
        async fn authenticate(&self, _token: &str) -> Result<SpiffeId, AuthnError> {
            Err(AuthnError::Unauthenticated(self.0.clone()))
        }
    }

    struct RecordingHook {
        calls: parking_lot::Mutex<Vec<(String, String)>>,
    }

    impl RejectHook for RecordingHook {
        async fn on_reject(&self, principal: &str, reason: &str) {
            self.calls
                .lock()
                .push((principal.to_owned(), reason.to_owned()));
        }
    }

    fn proxy_id() -> SpiffeId {
        SpiffeId::from_parts("cluster.local", "coxswain-system", "coxswain-proxy")
    }

    fn make_request(sa_token: &str, csr: &[u8]) -> Request<BootstrapRequest> {
        Request::new(BootstrapRequest {
            sa_token: sa_token.to_owned(),
            csr_pem: csr.to_vec(),
            wire_version: WIRE_VERSION,
            scope: None,
        })
    }

    fn resolver(shared_relay: Option<&str>, active: &[&str]) -> Arc<UpstreamResolverConfig> {
        let set: HashSet<String> = active.iter().map(|s| (*s).to_owned()).collect();
        Arc::new(UpstreamResolverConfig {
            controller_endpoint: "https://coxswain-controller-discovery.coxswain-system.svc:50051"
                .to_owned(),
            controller_sa: "coxswain-controller".to_owned(),
            shared_relay_endpoint: shared_relay.map(str::to_owned),
            relay_service_name: "coxswain-relay".to_owned(),
            relay_port: 50051,
            relay_sa: "coxswain-relay".to_owned(),
            active_relays: Shared::from_value(set),
        })
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn happy_path_returns_svid_and_bundle() {
        let cert = b"cert".to_vec();
        let bundle = b"bundle".to_vec();
        let svc = BootstrapService::new(
            Arc::new(OkIssuer {
                cert: cert.clone(),
                bundle: bundle.clone(),
                not_after: 9999,
            }),
            Arc::new(OkAuthenticator(proxy_id())),
        );

        let accepted_before = crate::metrics::bootstrap_total()
            .with_label_values(&["accepted", "ok"])
            .get();
        let issued_before = crate::metrics::svid_issued_total().get();

        let resp = svc
            .bootstrap(make_request("tok", b"csr"))
            .await
            .expect("should succeed");
        let body = resp.into_inner();
        assert_eq!(body.svid_cert_pem, cert);
        assert_eq!(body.trust_bundle_pem, bundle);
        assert_eq!(body.not_after_unix, 9999);

        // `>=`, not exact: `accepted,ok` and `svid_issued_total` are process-global
        // counters other bootstrap tests (e.g. the resolver test) also increment
        // when the in-process test runner schedules them concurrently. A monotone
        // counter still proves this accepted bootstrap incremented it.
        assert!(
            crate::metrics::bootstrap_total()
                .with_label_values(&["accepted", "ok"])
                .get()
                > accepted_before,
            "an accepted bootstrap must increment bootstrap_total{{accepted,ok}}"
        );
        assert!(
            crate::metrics::svid_issued_total().get() > issued_before,
            "an accepted bootstrap must increment svid_issued_total"
        );
    }

    #[tokio::test]
    async fn bad_sa_token_returns_unauthenticated_and_fires_hook() {
        let hook = Arc::new(RecordingHook {
            calls: parking_lot::Mutex::new(vec![]),
        });
        let svc = BootstrapService::with_reject_hook(
            Arc::new(OkIssuer {
                cert: vec![],
                bundle: vec![],
                not_after: 0,
            }),
            Arc::new(RejectAuthenticator("token expired".into())),
            hook.clone(),
        );

        let rejected_before = crate::metrics::bootstrap_total()
            .with_label_values(&["rejected", "sa_token"])
            .get();

        let err = svc
            .bootstrap(make_request("bad-token", b"csr"))
            .await
            .expect_err("should fail");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        assert_eq!(
            crate::metrics::bootstrap_total()
                .with_label_values(&["rejected", "sa_token"])
                .get(),
            rejected_before + 1,
            "a rejected SA token must increment bootstrap_total{{rejected,sa_token}}"
        );

        let calls = hook.calls.lock();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].1.contains("token expired"),
            "reason: {}",
            calls[0].1
        );
    }

    #[tokio::test]
    async fn ca_not_ready_returns_unavailable() {
        let svc = BootstrapService::new(
            Arc::new(FailIssuer(IssuerError::NotReady)),
            Arc::new(OkAuthenticator(proxy_id())),
        );
        let rejected_before = crate::metrics::bootstrap_total()
            .with_label_values(&["rejected", "ca_not_ready"])
            .get();

        let err = svc
            .bootstrap(make_request("tok", b"csr"))
            .await
            .expect_err("should fail");
        assert_eq!(err.code(), tonic::Code::Unavailable);

        assert_eq!(
            crate::metrics::bootstrap_total()
                .with_label_values(&["rejected", "ca_not_ready"])
                .get(),
            rejected_before + 1,
            "a not-ready CA must increment bootstrap_total{{rejected,ca_not_ready}}"
        );
    }

    #[tokio::test]
    async fn wrong_wire_version_returns_failed_precondition() {
        let svc = BootstrapService::new(
            Arc::new(OkIssuer {
                cert: vec![],
                bundle: vec![],
                not_after: 0,
            }),
            Arc::new(OkAuthenticator(proxy_id())),
        );
        let req = Request::new(BootstrapRequest {
            sa_token: "tok".into(),
            csr_pem: vec![],
            wire_version: WIRE_VERSION + 99,
            scope: None,
        });
        let rejected_before = crate::metrics::bootstrap_total()
            .with_label_values(&["rejected", "wire_version"])
            .get();

        let err = svc.bootstrap(req).await.expect_err("should fail");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);

        assert_eq!(
            crate::metrics::bootstrap_total()
                .with_label_values(&["rejected", "wire_version"])
                .get(),
            rejected_before + 1,
            "a wire-version mismatch must increment bootstrap_total{{rejected,wire_version}}"
        );
    }

    // NOTE: BootstrapService::stream is a one-line stub returning Status::unimplemented.
    // It cannot be easily unit-tested without constructing tonic::Streaming (an opaque type),
    // so coverage is provided by the integration tests that wire both listeners end-to-end.

    // ── best-upstream resolver (#601) ──────────────────────────────────────────

    fn dedicated_id(namespace: &str) -> SpiffeId {
        SpiffeId::from_parts("cluster.local", namespace, "my-gw-coxswain")
    }

    fn relay_id(namespace: &str) -> SpiffeId {
        SpiffeId::from_parts("cluster.local", namespace, "coxswain-relay")
    }

    #[test]
    fn dedicated_client_in_provisioned_namespace_points_at_relay() {
        let cfg = resolver(None, &["team-a"]);
        let (endpoint, sa) = cfg.resolve(
            &dedicated_id("team-a"),
            &Scope::Gateway {
                namespace: "team-a".to_owned(),
                name: "my-gw".to_owned(),
            },
        );
        assert_eq!(endpoint, "https://coxswain-relay.team-a.svc:50051");
        assert_eq!(sa, "coxswain-relay");
    }

    #[test]
    fn dedicated_client_without_relay_points_at_controller() {
        let cfg = resolver(None, &[]);
        let (endpoint, sa) = cfg.resolve(
            &dedicated_id("team-a"),
            &Scope::Gateway {
                namespace: "team-a".to_owned(),
                name: "my-gw".to_owned(),
            },
        );
        assert_eq!(
            endpoint,
            "https://coxswain-controller-discovery.coxswain-system.svc:50051"
        );
        assert_eq!(sa, "coxswain-controller");
    }

    #[test]
    fn relay_never_tiers_even_in_its_own_provisioned_namespace() {
        // A relay bootstraps in a namespace that is itself provisioned; it must
        // still be pointed at the controller, never at itself.
        let cfg = resolver(None, &["team-a"]);
        let (endpoint, sa) = cfg.resolve(
            &relay_id("team-a"),
            &Scope::Namespace {
                namespace: "team-a".to_owned(),
            },
        );
        assert_eq!(
            endpoint,
            "https://coxswain-controller-discovery.coxswain-system.svc:50051"
        );
        assert_eq!(sa, "coxswain-controller");
    }

    #[test]
    fn shared_pool_client_uses_shared_relay_when_present_else_controller() {
        let with_relay = resolver(
            Some("https://coxswain-relay-shared.coxswain-system.svc:50051"),
            &[],
        );
        let (endpoint, sa) = with_relay.resolve(&proxy_id(), &Scope::SharedPool);
        assert_eq!(
            endpoint,
            "https://coxswain-relay-shared.coxswain-system.svc:50051"
        );
        assert_eq!(sa, "coxswain-relay");

        let without = resolver(None, &[]);
        let (endpoint, sa) = without.resolve(&proxy_id(), &Scope::SharedPool);
        assert_eq!(
            endpoint,
            "https://coxswain-controller-discovery.coxswain-system.svc:50051"
        );
        assert_eq!(sa, "coxswain-controller");
    }

    #[tokio::test]
    async fn bootstrap_response_carries_resolved_upstream() {
        let svc = BootstrapService::new(
            Arc::new(OkIssuer {
                cert: b"cert".to_vec(),
                bundle: b"bundle".to_vec(),
                not_after: 9999,
            }),
            Arc::new(OkAuthenticator(dedicated_id("team-a"))),
        )
        .with_upstream_resolver(resolver(None, &["team-a"]));

        let req = Request::new(BootstrapRequest {
            sa_token: "tok".to_owned(),
            csr_pem: b"csr".to_vec(),
            wire_version: WIRE_VERSION,
            scope: Some(crate::wire::scope_to_wire(&Scope::Gateway {
                namespace: "team-a".to_owned(),
                name: "my-gw".to_owned(),
            })),
        });

        let body = svc
            .bootstrap(req)
            .await
            .expect("should succeed")
            .into_inner();
        assert_eq!(
            body.upstream_endpoint,
            "https://coxswain-relay.team-a.svc:50051"
        );
        assert_eq!(body.expected_server_sa, "coxswain-relay");
    }
}
