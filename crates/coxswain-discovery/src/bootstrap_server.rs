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

use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{info, warn};

use coxswain_core::identity::{
    AuthnError, CsrPem, IssuerError, SpiffeId, SvidIssuer, TokenAuthenticator,
};

use crate::proto::v1::{
    BootstrapRequest, BootstrapResponse, ClientMessage, ServerMessage, discovery_server::Discovery,
};
use crate::version::WIRE_VERSION;

// ── RejectHook ────────────────────────────────────────────────────────────────

/// Callback invoked when a Bootstrap request is rejected.
///
/// The controller wires this to its event recorder to emit a `BootstrapRejected`
/// Warning Event.  The discovery crate itself never touches the Kubernetes API.
pub trait RejectHook: Send + Sync {
    /// Called when a bootstrap request is rejected.  `principal` is the SA
    /// identity string extracted from the token (if authentication succeeded
    /// but something else failed), or the raw error context otherwise.
    fn on_reject(&self, principal: &str, reason: &str);
}

/// No-op reject hook used as the default when no event recorder is available.
// intentionally open: constructed as a unit struct literal `NoOpRejectHook` by callers
pub struct NoOpRejectHook;

impl RejectHook for NoOpRejectHook {
    fn on_reject(&self, _principal: &str, _reason: &str) {}
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
        }
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
    /// 3. Sign the CSR via [`SvidIssuer`] → [`IssuedSvid`].
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
            self.reject_hook.on_reject("<unknown>", &reason);
            return Err(Status::failed_precondition(reason));
        }

        // 2. Authenticate the SA token.
        let spiffe_id: SpiffeId = match self.authenticator.authenticate(&req.sa_token).await {
            Ok(id) => id,
            Err(AuthnError::Unauthenticated(msg)) => {
                warn!(reason = %msg, "bootstrap: SA token rejected");
                self.reject_hook.on_reject("<unauthenticated>", &msg);
                return Err(Status::unauthenticated(format!("SA token rejected: {msg}")));
            }
            Err(AuthnError::ApiError(msg)) => {
                warn!(reason = %msg, "bootstrap: TokenReview API error");
                self.reject_hook.on_reject("<api-error>", &msg);
                return Err(Status::internal(format!("TokenReview error: {msg}")));
            }
            Err(AuthnError::InvalidPrincipal(msg)) => {
                warn!(reason = %msg, "bootstrap: unexpected principal format");
                self.reject_hook.on_reject("<invalid-principal>", &msg);
                return Err(Status::unauthenticated(format!(
                    "unexpected principal: {msg}"
                )));
            }
            // AuthnError is #[non_exhaustive]; treat unknown variants as internal errors.
            Err(e) => {
                let msg = e.to_string();
                warn!(reason = %msg, "bootstrap: unexpected auth error");
                self.reject_hook.on_reject("<unknown>", &msg);
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
                self.reject_hook.on_reject(spiffe_id.as_str(), msg);
                return Err(Status::unavailable(msg));
            }
            Err(IssuerError::MalformedCsr(msg)) => {
                warn!(spiffe_id = %spiffe_id, reason = %msg, "bootstrap: malformed CSR");
                self.reject_hook.on_reject(spiffe_id.as_str(), &msg);
                return Err(Status::invalid_argument(format!("malformed CSR: {msg}")));
            }
            Err(IssuerError::Signing(msg)) => {
                warn!(spiffe_id = %spiffe_id, reason = %msg, "bootstrap: signing error");
                self.reject_hook.on_reject(spiffe_id.as_str(), &msg);
                return Err(Status::internal(format!("signing error: {msg}")));
            }
            // IssuerError is #[non_exhaustive]; treat unknown variants as internal errors.
            Err(e) => {
                let msg = e.to_string();
                warn!(spiffe_id = %spiffe_id, reason = %msg, "bootstrap: unexpected issuer error");
                self.reject_hook.on_reject(spiffe_id.as_str(), &msg);
                return Err(Status::internal(format!("issuer error: {msg}")));
            }
        };

        let trust_bundle = self.issuer.trust_bundle();

        info!(
            spiffe_id = %spiffe_id,
            not_after = svid.not_after_unix,
            "bootstrap: SVID issued"
        );

        Ok(Response::new(BootstrapResponse {
            svid_cert_pem: svid.cert_pem,
            trust_bundle_pem: trust_bundle,
            not_after_unix: svid.not_after_unix,
        }))
    }
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
        calls: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl RejectHook for RecordingHook {
        fn on_reject(&self, principal: &str, reason: &str) {
            self.calls
                .lock()
                .unwrap_or_else(|e| panic!("invariant: hook lock not poisoned: {e}"))
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

        let resp = svc
            .bootstrap(make_request("tok", b"csr"))
            .await
            .expect("should succeed");
        let body = resp.into_inner();
        assert_eq!(body.svid_cert_pem, cert);
        assert_eq!(body.trust_bundle_pem, bundle);
        assert_eq!(body.not_after_unix, 9999);
    }

    #[tokio::test]
    async fn bad_sa_token_returns_unauthenticated_and_fires_hook() {
        let hook = Arc::new(RecordingHook {
            calls: std::sync::Mutex::new(vec![]),
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

        let err = svc
            .bootstrap(make_request("bad-token", b"csr"))
            .await
            .expect_err("should fail");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        let calls = hook
            .calls
            .lock()
            .unwrap_or_else(|e| panic!("invariant: hook lock not poisoned: {e}"));
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
        let err = svc
            .bootstrap(make_request("tok", b"csr"))
            .await
            .expect_err("should fail");
        assert_eq!(err.code(), tonic::Code::Unavailable);
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
        });
        let err = svc.bootstrap(req).await.expect_err("should fail");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    // NOTE: BootstrapService::stream is a one-line stub returning Status::unimplemented.
    // It cannot be easily unit-tested without constructing tonic::Streaming (an opaque type),
    // so coverage is provided by the integration tests that wire both listeners end-to-end.
}
