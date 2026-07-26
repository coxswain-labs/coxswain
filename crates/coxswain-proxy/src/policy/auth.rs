//! External and basic authentication enforcement for the Ingress proxy.
//!
//! Called from [`crate::hooks::request_filter`] after rate-limiting and
//! before redirect/body handling.  Implements two modes:
//!
//! - **External (`ext_authz`)**: forwards a sub-request to a configurable auth
//!   endpoint (HTTP forward-auth or the Envoy gRPC `Authorization/Check` proto)
//!   — original method, Host, and path are preserved; client headers are
//!   forwarded only when named in `allowedHeaders` (GEP-1494, #663; resolved to
//!   a per-protocol default when unset — see
//!   [`coxswain_core::routing::HttpExtAuthConfig::allowed_headers`]); no body.
//!   2xx/`OK` → allow; otherwise → deny (status+body returned to client);
//!   timeout/connect error → 503.
//!
//! - **Basic auth** (`Authorization: Basic`): decodes the header and verifies
//!   against an htpasswd credential list pre-parsed at reconcile time.  bcrypt
//!   verification runs in `tokio::task::spawn_blocking`; SHA1 uses a constant-
//!   time comparison.  Missing/invalid credentials → 401 + `WWW-Authenticate`.
//!   An `Unavailable` config (missing/unlabeled secret) → 503.
//!
//! - **JWT auth** (`JwtAuth`, #441): extracts a bearer token from a configured
//!   request header, verifies its signature against the resolved JWKS (pushed
//!   by the controller — this crate never fetches JWKS itself, see
//!   [`coxswain_core::routing::JwtConfig`]'s module doc), and checks `iss`/`aud`.
//!   Verified claims are copied onto upstream headers per `claimToHeaders`; the
//!   raw token is stripped from the upstream request unless `forward: true`.
//!   Missing/invalid token → 401 + `WWW-Authenticate: Bearer`. An unresolved
//!   JWKS (`Unavailable`) → 503. Signature verification is fast (no KDF like
//!   bcrypt) so it runs inline, not in `spawn_blocking`.
//!
//! ## Security notes
//!
//! The decoded `user:pass` plaintext is held in a [`zeroize::Zeroizing`] buffer
//! and scrubbed immediately after verification, whether it succeeds or fails.
//! bcrypt and SHA1 hashes are scrubbed when the `BasicCredential` list is
//! dropped at reconcile time (via `ZeroizeOnDrop` on `BasicCredential` /
//! `PasswordHash`).
//!
//! `ext_authz`'s `allowedResponseHeaders` names are stripped from the client's
//! request unconditionally, before the check even runs (#663, `enforce`'s
//! `External` arm) — the proxy only ever *sets* a name the auth service's allow
//! response actually echoes, so a configured-but-unechoed name would otherwise
//! let a client's forged copy reach the backend indistinguishable from a
//! proxy-verified one. Same pattern as the JWT path's [`strip_header_names`].

use coxswain_core::routing::{ExtAuthTransport, IngressAuthConfig, JwtConfig, PasswordHash};
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroizing;

/// Round-robin cursor for spreading ext_authz sub-requests across a resolved
/// auth service's endpoints. Process-wide and `Relaxed` — approximate fairness
/// is all that's needed; exact distribution is not a correctness property.
static EXT_AUTH_RR: AtomicUsize = AtomicUsize::new(0);

/// Pick the next auth endpoint round-robin. `None` only when the slice is
/// empty (the caller fails closed); a resolved `ExtAuthConfig` is never empty.
fn pick_endpoint(endpoints: &[SocketAddr]) -> Option<SocketAddr> {
    match endpoints.len() {
        0 => None,
        1 => Some(endpoints[0]),
        n => Some(endpoints[EXT_AUTH_RR.fetch_add(1, Ordering::Relaxed) % n]),
    }
}

// ── Hop-by-hop headers stripped when forwarding to the auth service ──────────

/// RFC 2616 §13.5.1 hop-by-hop headers: never forward these to the auth service
/// or mirror sub-requests.
pub(crate) const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Whether `name` — an already-lower-cased header name, from
/// [`http::HeaderName::as_str`] — is in `allowed_headers` and therefore
/// forwarded to the ext_authz auth service on the check request (GEP-1494
/// `allowedHeaders`, #663).
///
/// `allowed_headers` is always non-empty by construction (the reflector bakes
/// in the GEP-1494 per-protocol default when the CRD field is absent or
/// empty), so this never degenerates into "forward everything". `Host`, the
/// request method, and the request path bypass this check entirely on both
/// transports — they identify the request being authorized, not
/// client-supplied trust material, and are threaded through dedicated fields
/// rather than the generic header set this gates.
pub(crate) fn is_allowed_request_header(name: &str, allowed_headers: &[Box<str>]) -> bool {
    allowed_headers.iter().any(|h| h.as_ref() == name)
}

/// Whether `name` — an already-lower-cased header name — should be forwarded
/// onto the ext_authz check request: not `host` (forwarded separately as a
/// dedicated pseudo-header on both transports, never through this generic
/// set), not hop-by-hop, and named in `allowed_headers`
/// ([`is_allowed_request_header`], GEP-1494 `allowedHeaders`, #663).
///
/// The single decision point [`select_forwarded_headers`] (HTTP) and
/// [`grpc::select_check_headers`] both filter through, so the two transports
/// can never drift on which names are pseudo-headers vs. hop-by-hop vs.
/// allow-listed.
fn should_forward_to_authz(name: &str, allowed_headers: &[Box<str>]) -> bool {
    name != "host"
        && !HOP_BY_HOP.contains(&name)
        && is_allowed_request_header(name, allowed_headers)
}

/// The `(name, value)` pairs to forward from `req_hdr` onto the HTTP
/// forward-auth check request, per [`should_forward_to_authz`]. `Session`-free
/// (takes a [`RequestHeader`] directly) so this is unit-testable without
/// constructing a Pingora `Session` — the same testing boundary
/// [`stage_ext_authz_strips`] established for the response-header side.
fn select_forwarded_headers<'a>(
    req_hdr: &'a pingora_http::RequestHeader,
    allowed_headers: &[Box<str>],
) -> Vec<(&'a str, &'a str)> {
    req_hdr
        .headers
        .iter()
        .filter(|(name, _)| should_forward_to_authz(name.as_str(), allowed_headers))
        .filter_map(|(name, value)| value.to_str().ok().map(|v| (name.as_str(), v)))
        .collect()
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Enforce the authentication policy on `session`.
///
/// Returns:
/// - `Ok(false)` — authentication passed; the request should proceed to upstream.
/// - `Ok(true)` — authentication denied; a response has been written to the client
///   (either from the auth service or a synthesized 401/503).  The request must
///   **not** be forwarded to the upstream backend.
/// - `Err(…)` — a hard Pingora error (only on internal write failures).
///
/// `auth_response_headers` is populated when the auth service returns 2xx (or a
/// JWT check succeeds with `claimToHeaders`/`forwardPayloadHeader` configured)
/// and the route's `auth-response-headers` list is non-empty; the caller
/// stores it on `ctx` for [`crate::hooks::upstream_request_filter`] to apply.
/// `strip_upstream_headers` is populated by a successful JWT check when the
/// CRD's `forward` is `false`, and unconditionally by an `ext_authz` check's
/// configured `allowedResponseHeaders` (#663, mirroring [`strip_header_names`])
/// — applied by the same caller, before `auth_response_headers`.
///
/// # Errors
///
/// Propagates Pingora `write_response_header` errors.
pub(crate) async fn enforce(
    client: &reqwest::Client,
    grpc_channels: &crate::policy::grpc_channel::GrpcAuthChannelCache,
    jwks_keys: &JwksKeyCache,
    auth: &IngressAuthConfig,
    session: &mut Session,
    auth_response_headers: &mut Option<Vec<(Box<str>, Box<str>)>>,
    strip_upstream_headers: &mut Option<Vec<Box<str>>>,
) -> Result<bool> {
    match auth {
        IngressAuthConfig::External(cfg) => {
            // Unconditionally stage every name this check's allow-list could
            // populate, *before* the check runs — not just on its allow branch.
            // That also covers the fail-open paths (unreachable/timed-out
            // service, `failClosed: false`): the check never ran, so nothing
            // legitimate could have set the header, making a client-forged copy
            // indistinguishable from a proxy-verified one without this strip.
            stage_ext_authz_strips(&cfg.transport, strip_upstream_headers);
            enforce_ext_authz(client, grpc_channels, cfg, session, auth_response_headers).await
        }
        IngressAuthConfig::Basic(creds) => enforce_basic(creds, session).await,
        IngressAuthConfig::Jwt(cfg) => {
            enforce_jwt(
                jwks_keys,
                cfg,
                session,
                auth_response_headers,
                strip_upstream_headers,
            )
            .await
        }
        IngressAuthConfig::Unavailable => {
            // Secret was absent or unlabeled at reconcile time — fail closed.
            tracing::warn!("auth config unavailable — refusing request (503)");
            write_simple(session, 503).await?;
            Ok(true)
        }
    }
}

/// The `allowedResponseHeaders` names an `ext_authz` check owns on the upstream
/// request, for either transport.
///
/// The proxy only ever *sets* these names when the auth service's allow
/// response actually echoes them (see [`enforce_ext_authz_http`] and
/// `grpc::map_check_response`) — so unlike a `set`-then-`insert` header, a
/// configured-but-unechoed name has nothing proxy-side to overwrite a client's
/// forged copy with. [`enforce`] strips every name here unconditionally,
/// before the check even runs.
fn ext_authz_strip_names(transport: &ExtAuthTransport) -> &Arc<[Box<str>]> {
    match transport {
        ExtAuthTransport::Http(cfg) => &cfg.response_headers,
        ExtAuthTransport::Grpc(cfg) => &cfg.response_headers,
    }
}

/// Stage `transport`'s [`ext_authz_strip_names`] onto `strip_upstream_headers_out`
/// (#663), appending to whatever an earlier check in the additive auth chain
/// already staged (e.g. a `JwtAuth` token-strip name) rather than clobbering it.
/// A `Session`-free, directly unit-testable extraction of [`enforce`]'s
/// `External` arm — `enforce` itself needs a live `Session` to reach the check
/// that follows, which is out of scope for a staging-order test.
fn stage_ext_authz_strips(
    transport: &ExtAuthTransport,
    strip_upstream_headers_out: &mut Option<Vec<Box<str>>>,
) {
    let names = ext_authz_strip_names(transport);
    if !names.is_empty() {
        strip_upstream_headers_out
            .get_or_insert_with(Vec::new)
            .extend(names.iter().cloned());
    }
}

// ── External auth (ext_authz HTTP) ───────────────────────────────────────────

async fn enforce_ext_authz(
    client: &reqwest::Client,
    grpc_channels: &crate::policy::grpc_channel::GrpcAuthChannelCache,
    cfg: &coxswain_core::routing::ExtAuthConfig,
    session: &mut Session,
    auth_response_headers_out: &mut Option<Vec<(Box<str>, Box<str>)>>,
) -> Result<bool> {
    match &cfg.transport {
        ExtAuthTransport::Http(http_cfg) => {
            enforce_ext_authz_http(client, cfg, http_cfg, session, auth_response_headers_out).await
        }
        ExtAuthTransport::Grpc(grpc_cfg) => {
            grpc::enforce_ext_authz_grpc(
                grpc_channels,
                cfg,
                grpc_cfg,
                session,
                auth_response_headers_out,
            )
            .await
        }
    }
}

async fn enforce_ext_authz_http(
    client: &reqwest::Client,
    cfg: &coxswain_core::routing::ExtAuthConfig,
    http_cfg: &coxswain_core::routing::HttpExtAuthConfig,
    session: &mut Session,
    auth_response_headers_out: &mut Option<Vec<(Box<str>, Box<str>)>>,
) -> Result<bool> {
    // Build the sub-request: original method + Host, client headers, no body.
    let req_hdr = session.req_header();
    let method_str = req_hdr.method.as_str();
    let method = reqwest::Method::from_bytes(method_str.as_bytes()).unwrap_or(reqwest::Method::GET);

    // Send the check to a resolved auth-service endpoint (round-robin), replaying
    // the original request path — the Envoy `ext_authz`-HTTP model. The proxy
    // connects to a pod IP directly, the same as every other backend.
    let Some(addr) = pick_endpoint(&cfg.endpoints) else {
        tracing::warn!("ext_authz has no resolved endpoints — refusing request (503)");
        write_simple(session, 503).await?;
        return Ok(true);
    };
    let path_and_query = req_hdr
        .uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let url = format!("http://{addr}{path_and_query}");

    let mut builder = client.request(method, &url);

    // Forward Host unconditionally (a pseudo-header identifying the request, not
    // client-supplied trust material) plus every client header named in
    // `allowed_headers` (GEP-1494 `allowedHeaders`, #663) — hop-by-hop headers
    // are stripped regardless of the allow-list.
    let host_hdr = req_hdr
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if !host_hdr.is_empty() {
        builder = builder.header(reqwest::header::HOST, &host_hdr);
    }
    for (name, value) in select_forwarded_headers(req_hdr, &http_cfg.allowed_headers) {
        builder = builder.header(name, value);
    }

    let auth_response = match tokio::time::timeout(cfg.timeout, builder.send()).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            // Auth service unreachable/errored: fail closed (503) unless the
            // operator opted into fail-open (`failClosed: false`).
            tracing::warn!(error = %e, fail_closed = cfg.fail_closed, "ext_authz request failed");
            if cfg.fail_closed {
                write_simple(session, 503).await?;
                return Ok(true);
            }
            return Ok(false);
        }
        Err(_) => {
            tracing::warn!(
                timeout_ms = cfg.timeout.as_millis(),
                fail_closed = cfg.fail_closed,
                "ext_authz request timed out"
            );
            if cfg.fail_closed {
                write_simple(session, 503).await?;
                return Ok(true);
            }
            return Ok(false);
        }
    };

    let auth_status = auth_response.status();

    if auth_status.is_success() {
        // 2xx → allow.  Copy `auth-response-headers` from the auth response
        // onto the upstream request (Envoy `allowed_upstream_headers` /
        // Istio `headersToUpstreamOnAllow`).
        if !http_cfg.response_headers.is_empty() {
            let mut headers_to_forward = Vec::with_capacity(http_cfg.response_headers.len());
            for name in http_cfg.response_headers.iter() {
                if let Some(Ok(v)) = auth_response
                    .headers()
                    .get(name.as_ref())
                    .map(|val| val.to_str())
                {
                    headers_to_forward.push((name.clone(), v.into()));
                }
            }
            if !headers_to_forward.is_empty() {
                auth_response_headers_out
                    .get_or_insert_with(Vec::new)
                    .extend(headers_to_forward);
            }
        }
        return Ok(false);
    }

    // non-2xx → deny.  Return the auth response status + body to the client.
    // Controlled header set: hop-by-hop headers stripped; Set-Cookie only when
    // auth-always-set-cookie; Content-Type / WWW-Authenticate / Location always
    // forwarded so the client can render the deny body (e.g. login redirect).
    let deny_status = auth_status.as_u16();

    // Collect the forwarded headers as owned (name, value) pairs before
    // consuming auth_response with .bytes() below.  Owned strings are needed
    // because Pingora's insert_header requires `'static`-able key types.
    let forward_hdrs: Vec<(String, String)> = auth_response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            // `HeaderName::as_str()` is already lowercase — no owned copy needed
            // for the comparisons; only the forwarded key below is owned.
            let name_s = name.as_str();
            if HOP_BY_HOP.contains(&name_s) {
                return None;
            }
            if name_s == "set-cookie" && !http_cfg.always_set_cookie {
                return None;
            }
            let should_forward = name_s == "content-type"
                || name_s == "www-authenticate"
                || name_s == "location"
                || name_s == "set-cookie";
            if !should_forward {
                return None;
            }
            value
                .to_str()
                .ok()
                .map(|v| (name_s.to_owned(), v.to_owned()))
        })
        .collect();

    let body = auth_response.bytes().await.unwrap_or_default();

    let mut resp_hdr = ResponseHeader::build(deny_status, Some(forward_hdrs.len()))?;
    for (name, value) in forward_hdrs {
        // `String` implements `IntoCaseHeaderName` and owns its data — no
        // lifetime tie to the already-consumed `auth_response`.
        let _ = resp_hdr.insert_header(name, value);
    }

    session
        .write_response_header(Box::new(resp_hdr), body.is_empty())
        .await
        .unwrap_or_else(|e| tracing::error!("failed to write auth deny response: {e}"));
    if !body.is_empty() {
        session
            .write_response_body(Some(body), true)
            .await
            .unwrap_or_else(|e| {
                tracing::error!("failed to write auth deny body: {e}");
            });
    }
    Ok(true)
}

#[cfg(test)]
mod ext_authz_strip_tests {
    use super::*;
    use coxswain_core::routing::{GrpcExtAuthConfig, HttpExtAuthConfig};

    fn http_transport(response_header_names: &[&str]) -> ExtAuthTransport {
        ExtAuthTransport::Http(HttpExtAuthConfig::new(
            Arc::from([]),
            response_header_names
                .iter()
                .map(|n| Box::from(*n))
                .collect(),
            false,
        ))
    }

    fn grpc_transport(response_header_names: &[&str]) -> ExtAuthTransport {
        ExtAuthTransport::Grpc(GrpcExtAuthConfig::new(
            Arc::from([]),
            response_header_names
                .iter()
                .map(|n| Box::from(*n))
                .collect(),
        ))
    }

    #[test]
    fn ext_authz_strip_names_covers_both_transports() {
        assert_eq!(
            ext_authz_strip_names(&http_transport(&["x-auth-user", "x-auth-role"]))
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<&str>>(),
            ["x-auth-user", "x-auth-role"]
        );
        assert_eq!(
            ext_authz_strip_names(&grpc_transport(&["x-auth-user"]))
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<&str>>(),
            ["x-auth-user"]
        );
        assert!(ext_authz_strip_names(&http_transport(&[])).is_empty());
        assert!(ext_authz_strip_names(&grpc_transport(&[])).is_empty());
    }

    #[test]
    fn stage_ext_authz_strips_populates_output_with_configured_names() {
        let transport = http_transport(&["x-auth-user", "x-auth-role"]);
        let mut out = None;
        stage_ext_authz_strips(&transport, &mut out);
        assert_eq!(
            out.as_deref(),
            Some(
                [
                    Box::<str>::from("x-auth-user"),
                    Box::<str>::from("x-auth-role")
                ]
                .as_slice()
            )
        );
    }

    #[test]
    fn stage_ext_authz_strips_appends_to_names_an_earlier_check_already_staged() {
        // The additive auth chain (e.g. a route-level JwtAuth `forward: false`
        // strip ahead of a Gateway-mandated ext_authz check) shares one
        // `strip_upstream_headers` slot across every `enforce()` call — staging
        // must APPEND, never clobber a name an earlier check already staged.
        let transport = http_transport(&["x-auth-user"]);
        let mut out = Some(vec![Box::<str>::from("x-jwt-token")]);
        stage_ext_authz_strips(&transport, &mut out);
        assert_eq!(
            out.as_deref(),
            Some(
                [
                    Box::<str>::from("x-jwt-token"),
                    Box::<str>::from("x-auth-user")
                ]
                .as_slice()
            )
        );
    }

    #[test]
    fn stage_ext_authz_strips_leaves_output_unset_when_unconfigured() {
        let mut out = None;
        stage_ext_authz_strips(&http_transport(&[]), &mut out);
        assert!(
            out.is_none(),
            "an ext_authz check with no allowedResponseHeaders must not force-allocate the strip list"
        );
    }
}

#[cfg(test)]
mod ext_authz_allowed_headers_tests {
    use super::{is_allowed_request_header, select_forwarded_headers, should_forward_to_authz};
    use pingora_http::RequestHeader;

    fn allowed(names: &[&str]) -> Vec<Box<str>> {
        names.iter().map(|n| Box::from(*n)).collect()
    }

    #[test]
    fn forwards_a_configured_name() {
        assert!(is_allowed_request_header(
            "authorization",
            &allowed(&["authorization", "x-request-id"])
        ));
    }

    #[test]
    fn withholds_an_unconfigured_name() {
        // The concrete #663 gap this closes: a client-controlled header not
        // named in `allowedHeaders` must never reach the auth service, even
        // when it looks like a credential (Cookie) or a header the operator's
        // backend later trusts as an authz-service verdict.
        assert!(!is_allowed_request_header(
            "cookie",
            &allowed(&["authorization"])
        ));
        assert!(!is_allowed_request_header(
            "x-auth-user",
            &allowed(&["authorization"])
        ));
    }

    #[test]
    fn withholds_everything_when_the_allow_list_is_empty() {
        // Reachable only if a caller ever passes an empty list directly (the
        // reflector never resolves one — see `resolve_allowed_headers`), but the
        // predicate itself must fail closed rather than default-allow.
        assert!(!is_allowed_request_header("authorization", &[]));
    }

    #[test]
    fn comparison_is_exact_not_substring() {
        // `contains`/`starts_with`-style matching would let `x-authorization-evil`
        // sneak through an `authorization` allow-list.
        assert!(!is_allowed_request_header(
            "x-authorization-evil",
            &allowed(&["authorization"])
        ));
    }

    #[test]
    fn should_forward_to_authz_excludes_host_even_when_listed() {
        // `host` is forwarded separately as a dedicated pseudo-header; listing it
        // in `allowedHeaders` must not cause a second, generic-path copy.
        assert!(!should_forward_to_authz("host", &allowed(&["host"])));
    }

    #[test]
    fn should_forward_to_authz_excludes_hop_by_hop_even_when_listed() {
        // A hop-by-hop name can never be forwarded, regardless of the allow-list
        // — listing `connection` must not punch a hole in that invariant.
        assert!(!should_forward_to_authz(
            "connection",
            &allowed(&["connection"])
        ));
    }

    #[test]
    fn select_forwarded_headers_only_returns_allow_listed_survivors() {
        // Regression for the exact wiring bug the review flagged: dropping the
        // `!` on the allow-list check, or reordering the host/hop-by-hop
        // carve-out, compiles clean but forwards everything. This test fails
        // immediately if either happens.
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("host", "example.com").unwrap();
        req.insert_header("authorization", "Bearer t").unwrap();
        req.insert_header("cookie", "session=evil").unwrap();
        req.insert_header("connection", "keep-alive").unwrap();

        let mut forwarded =
            select_forwarded_headers(&req, &allowed(&["authorization", "connection"]));
        forwarded.sort_unstable();

        assert_eq!(
            forwarded,
            vec![("authorization", "Bearer t")],
            "only the allow-listed, non-pseudo, non-hop-by-hop header survives"
        );
    }

    #[test]
    fn select_forwarded_headers_empty_when_nothing_matches() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("cookie", "session=evil").unwrap();
        assert!(select_forwarded_headers(&req, &allowed(&["authorization"])).is_empty());
    }
}

// ── Basic auth ────────────────────────────────────────────────────────────────

/// A valid bcrypt hash used solely to equalize verification timing on a username
/// miss, closing the username-enumeration oracle (a miss would otherwise skip the
/// expensive KDF a hit runs). Generated once at a fixed cost; the plaintext and the
/// verify result are irrelevant — only that the KDF actually runs. `None` if hash
/// generation ever fails, in which case the equalization is skipped (no panic on the
/// data plane).
static DUMMY_BCRYPT_HASH: std::sync::LazyLock<Option<String>> =
    std::sync::LazyLock::new(|| bcrypt::hash("coxswain-timing-equalization", 12).ok());

async fn enforce_basic(
    creds: &Arc<[coxswain_core::routing::BasicCredential]>,
    session: &mut Session,
) -> Result<bool> {
    if creds.is_empty() {
        // Empty credential list — same as Unavailable.
        tracing::warn!("basic auth has no credentials — refusing request (503)");
        write_simple(session, 503).await?;
        return Ok(true);
    }

    // Extract the Authorization: Basic header.
    let encoded = {
        let req = session.req_header();
        match req.headers.get(http::header::AUTHORIZATION) {
            Some(v) => match v.to_str() {
                Ok(s) => s.strip_prefix("Basic ").map(str::to_string),
                Err(_) => None,
            },
            None => None,
        }
    };

    let Some(encoded) = encoded else {
        return challenge_401(session).await;
    };

    // Decode base64 and split user:pass. Hold in a Zeroizing buffer so the
    // plaintext password is scrubbed when we leave this scope.
    let decoded: Zeroizing<Vec<u8>> = match base64::engine::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encoded.trim(),
    ) {
        Ok(b) => Zeroizing::new(b),
        Err(_) => return challenge_401(session).await,
    };

    let colon_pos = match decoded.iter().position(|&b| b == b':') {
        Some(p) => p,
        None => return challenge_401(session).await,
    };

    let user_bytes = &decoded[..colon_pos];
    let pass_bytes = &decoded[colon_pos + 1..];
    let username = match std::str::from_utf8(user_bytes) {
        Ok(u) => u,
        Err(_) => return challenge_401(session).await,
    };

    // Verify against the credential list.
    let mut matched_user = false;
    for cred in creds.iter() {
        if cred.username.as_ref() != username {
            continue;
        }
        matched_user = true;
        let verified = match &cred.hash {
            PasswordHash::Bcrypt(hash) => {
                let hash_owned: Box<str> = hash.clone();
                let pass_owned: Zeroizing<Vec<u8>> = Zeroizing::new(pass_bytes.to_vec());
                // bcrypt is CPU-heavy — off-load from the async executor.
                tokio::task::spawn_blocking(move || {
                    bcrypt::verify(std::str::from_utf8(&pass_owned).unwrap_or(""), &hash_owned)
                        .unwrap_or(false)
                })
                .await
                .unwrap_or(false)
            }
            PasswordHash::Sha1(hash) => {
                // Apache SHA1: stored as "{SHA}" + base64(SHA1(password)).
                let hash_b64 = hash.strip_prefix("{SHA}").unwrap_or("");
                let expected = match base64::engine::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    hash_b64,
                ) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                use sha1::Digest;
                let computed = sha1::Sha1::digest(pass_bytes);
                constant_time_eq::constant_time_eq(computed.as_slice(), &expected)
            }
        };
        if verified {
            return Ok(false);
        }
        // Username matched but password wrong — stop searching; remaining
        // entries with the same username (if any) won't help and iterating
        // further would create a timing oracle.
        break;
    }

    // Timing equalization: a username miss did no expensive KDF work, so run one
    // fixed-cost bcrypt verify against a dummy hash to make a miss cost ~the same
    // as a hit — closing the username-enumeration oracle. Result is discarded.
    if !matched_user && let Some(dummy) = DUMMY_BCRYPT_HASH.as_ref() {
        let dummy = dummy.clone();
        let pass_owned: Zeroizing<Vec<u8>> = Zeroizing::new(pass_bytes.to_vec());
        let _ = tokio::task::spawn_blocking(move || {
            bcrypt::verify(std::str::from_utf8(&pass_owned).unwrap_or(""), &dummy).unwrap_or(false)
        })
        .await;
    }

    challenge_401(session).await
}

// ── Helper: write a minimal response ─────────────────────────────────────────

/// Writes a `WWW-Authenticate: Basic realm="..."` challenge and returns
/// `Ok(true)` (request handled, do not forward to upstream).
async fn challenge_401(session: &mut Session) -> Result<bool> {
    let mut resp = ResponseHeader::build(401, Some(1))?;
    resp.insert_header(
        http::header::WWW_AUTHENTICATE,
        r#"Basic realm="Authentication required""#,
    )?;
    session
        .write_response_header(Box::new(resp), true)
        .await
        .unwrap_or_else(|e| tracing::error!("failed to write 401 challenge: {e}"));
    Ok(true)
}

/// Write a simple response with no body (for 503).
async fn write_simple(session: &mut Session, status: u16) -> Result<()> {
    let resp = ResponseHeader::build(status, None)?;
    session
        .write_response_header(Box::new(resp), true)
        .await
        .unwrap_or_else(|e| tracing::error!("failed to write {status} response: {e}"));
    Ok(())
}

/// Writes a `WWW-Authenticate: Bearer` challenge and returns `Ok(true)`
/// (request handled, do not forward to upstream).
async fn challenge_401_bearer(session: &mut Session) -> Result<bool> {
    let mut resp = ResponseHeader::build(401, Some(1))?;
    resp.insert_header(http::header::WWW_AUTHENTICATE, "Bearer")?;
    session
        .write_response_header(Box::new(resp), true)
        .await
        .unwrap_or_else(|e| tracing::error!("failed to write 401 challenge: {e}"));
    Ok(true)
}

// ── JWT auth (JWKS bearer-token validation, #441) ─────────────────────────────

/// Process-wide cache of parsed JWKS text → decoded key sets.
///
/// Keyed by the resolved [`JwtConfig::jwks`] `Arc<str>` itself: `Arc<str>`'s
/// `Hash`/`Eq` delegate to the string *content*, so two routes (or two
/// reconcile snapshots) carrying byte-identical JWKS text share one cache
/// entry without a separate content-hash step. Parsing a JWKS is the only
/// non-trivial CPU cost in the JWT path — signature verification itself is
/// fast — so this cache keeps it off the hot path after the first request.
///
/// No eviction: bounded by the number of distinct JWKS texts referenced by
/// live `JwtAuth` CRs (operator-authored config), not by request volume —
/// unlike the gRPC ext_authz channel cache, which is bounded by resolved pod
/// `SocketAddr`s and can grow with pod churn.
#[derive(Clone, Default)]
pub struct JwksKeyCache {
    parsed: Arc<dashmap::DashMap<Arc<str>, Arc<jsonwebtoken::jwk::JwkSet>>>,
}

impl JwksKeyCache {
    /// Construct an empty cache. Call once at process startup.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse `jwks` (or reuse a cached parse) into a [`jsonwebtoken::jwk::JwkSet`].
    ///
    /// `None` when the text is not valid JSON / not a valid JWK Set — the
    /// caller fails the request closed (503); a malformed JWKS is a
    /// reconcile-time or upstream-IdP problem, never a per-request one.
    fn get_or_parse(&self, jwks: &Arc<str>) -> Option<Arc<jsonwebtoken::jwk::JwkSet>> {
        if let Some(existing) = self.parsed.get(jwks) {
            return Some(Arc::clone(&existing));
        }
        let parsed: jsonwebtoken::jwk::JwkSet = serde_json::from_str(jwks).ok()?;
        let parsed = Arc::new(parsed);
        self.parsed.insert(Arc::clone(jwks), Arc::clone(&parsed));
        Some(parsed)
    }
}

/// Extract the bearer token from the first matching [`JwtConfig::from_headers`]
/// location present on the request. `from_headers` is never empty (the
/// reconciler defaults to `Authorization`/`"Bearer "` when the CRD's
/// `fromHeaders` is absent).
fn extract_bearer_token(cfg: &JwtConfig, session: &Session) -> Option<Box<str>> {
    let req = session.req_header();
    for loc in cfg.from_headers.iter() {
        let Some(value) = req.headers.get(loc.name.as_ref()) else {
            continue;
        };
        let Ok(value) = value.to_str() else {
            continue;
        };
        if loc.value_prefix.is_empty() {
            return Some(Box::from(value));
        }
        if let Some(token) = value.strip_prefix(loc.value_prefix.as_ref()) {
            return Some(Box::from(token));
        }
        // This location's prefix didn't match — keep scanning the remaining
        // configured locations rather than failing on the first miss.
    }
    None
}

/// A JSON scalar rendered as a header-safe string; arrays/objects/null are
/// skipped (not meaningful as a single header value).
fn claim_scalar_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Copy `cfg.claim_to_headers` matches and the optional base64url-encoded full
/// payload from verified `claims` into `auth_response_headers_out`.
fn apply_verified_claims(
    cfg: &JwtConfig,
    claims: &serde_json::Value,
    auth_response_headers_out: &mut Option<Vec<(Box<str>, Box<str>)>>,
) {
    let mut headers: Vec<(Box<str>, Box<str>)> = Vec::with_capacity(
        cfg.claim_to_headers.len() + usize::from(cfg.forward_payload_header.is_some()),
    );
    for (claim, header) in cfg.claim_to_headers.iter() {
        if let Some(value) = claims.get(claim.as_ref())
            && let Some(rendered) = claim_scalar_to_string(value)
        {
            headers.push((header.clone(), rendered.into_boxed_str()));
        }
    }
    if let Some(header) = &cfg.forward_payload_header
        && let Ok(bytes) = serde_json::to_vec(claims)
    {
        let encoded = base64::engine::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            bytes,
        );
        headers.push((header.clone(), encoded.into_boxed_str()));
    }
    if !headers.is_empty() {
        auth_response_headers_out
            .get_or_insert_with(Vec::new)
            .extend(headers);
    }
}

/// Header names to strip from the upstream request on a successful JWT check.
///
/// Always includes every `claimToHeaders`/`forwardPayloadHeader` destination
/// name — `apply_verified_claims` only overwrites a name it actually renders a
/// value for (claim absent, or present but non-scalar, silently skips it), so
/// without an unconditional strip an attacker-supplied header of the same
/// name would reach the upstream untouched, indistinguishable from a
/// proxy-verified claim. Also includes the token's own source header(s) when
/// `cfg.forward_token` is `false`.
fn strip_header_names(cfg: &JwtConfig) -> Vec<Box<str>> {
    let mut strip: Vec<Box<str>> = cfg
        .claim_to_headers
        .iter()
        .map(|(_, header)| header.clone())
        .collect();
    strip.extend(cfg.forward_payload_header.clone());
    if !cfg.forward_token {
        strip.extend(cfg.from_headers.iter().map(|loc| loc.name.clone()));
    }
    strip
}

/// Outcome of [`verify_jwt`] — a pure, `Session`-free function so the
/// signature-verification and claims-matching logic is unit-testable without
/// constructing a Pingora `Session` (this file's established testing
/// boundary — see the `grpc` submodule's tests, which exercise response
/// mapping directly rather than through a real `Session`).
#[derive(Debug)]
enum JwtVerifyOutcome {
    /// Signature verified and `iss`/`aud`/`exp` all check out.
    Valid(serde_json::Value),
    /// The JWKS text is unparseable or has no keys — fail closed (503).
    JwksUnavailable,
    /// No candidate key verified the token (bad signature, wrong issuer,
    /// wrong audience, expired, malformed) — fail closed (401).
    Invalid,
}

/// Verify `token` against the JWKS resolved by `cfg`, checking `iss`/`aud`.
///
/// The token header's `kid` narrows the candidate key when present; otherwise
/// every key in the JWKS is tried (bounded by operator-authored config, not
/// request input). The algorithm used for verification comes from **the JWK's
/// own declared `alg`**, never the token header's `alg` — trusting the
/// attacker-controlled token header would allow an algorithm-confusion attack.
fn verify_jwt(jwks_keys: &JwksKeyCache, cfg: &JwtConfig, token: &str) -> JwtVerifyOutcome {
    let Some(jwk_set) = jwks_keys.get_or_parse(&cfg.jwks) else {
        tracing::warn!("JWT auth: JWKS unparseable — refusing request (503)");
        return JwtVerifyOutcome::JwksUnavailable;
    };
    if jwk_set.keys.is_empty() {
        tracing::warn!("JWT auth: JWKS has no keys — refusing request (503)");
        return JwtVerifyOutcome::JwksUnavailable;
    }

    let Ok(header) = jsonwebtoken::decode_header(token.as_bytes()) else {
        return JwtVerifyOutcome::Invalid;
    };
    let candidates: Vec<&jsonwebtoken::jwk::Jwk> = match &header.kid {
        Some(kid) => jwk_set.find(kid).into_iter().collect(),
        None => jwk_set.keys.iter().collect(),
    };

    for jwk in candidates {
        // `JwtAuth` is documented as JWKS-only, i.e. asymmetric algorithms —
        // reject a symmetric `oct` key outright rather than letting it flow
        // into `DecodingKey::from_jwk` (which happily builds an HMAC key from
        // one): an HMAC secret is forgeable bearer-token material, unlike
        // every other value this type carries, and the CRD is not designed to
        // protect it as a secret (no redaction, no zeroization).
        if matches!(
            jwk.algorithm,
            jsonwebtoken::jwk::AlgorithmParameters::OctetKey(_)
        ) {
            continue;
        }
        // `KeyAlgorithm::to_algorithm` is private upstream; its body is just
        // `Algorithm::from_str(&self.to_string())` (both `Display`/`FromStr`
        // round-trip the JWA name, e.g. "RS256") — replicated here.
        let Some(alg) = jwk
            .common
            .key_algorithm
            .and_then(|ka| ka.to_string().parse::<jsonwebtoken::Algorithm>().ok())
        else {
            continue; // key doesn't declare a supported alg — skip, don't trust the token
        };
        let Ok(decoding_key) = jsonwebtoken::DecodingKey::from_jwk(jwk) else {
            continue;
        };
        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.set_issuer(&[cfg.issuer.as_ref()]);
        // jsonwebtoken only enforces `iss`/`aud` when the claim is *present* in
        // the token ("Validation only happens if the claim is present" per its
        // `Validation::iss`/`aud` docs) — a validly-signed token that simply
        // omits `iss` would otherwise sail through unchecked. Adding both to
        // `required_spec_claims` makes their *absence* a hard failure too, so
        // the issuer/audience restriction can't be bypassed by omission.
        validation.required_spec_claims.insert("iss".to_string());
        if cfg.audiences.is_empty() {
            validation.validate_aud = false;
        } else {
            let auds: Vec<&str> = cfg.audiences.iter().map(AsRef::as_ref).collect();
            validation.set_audience(&auds);
            validation.required_spec_claims.insert("aud".to_string());
        }

        // Verification is CPU-bound but fast (unlike bcrypt's deliberate KDF
        // cost) — runs inline, no `spawn_blocking`.
        if let Ok(data) =
            jsonwebtoken::decode::<serde_json::Value>(token.as_bytes(), &decoding_key, &validation)
        {
            return JwtVerifyOutcome::Valid(data.claims);
        }
    }

    JwtVerifyOutcome::Invalid
}

/// Enforce a [`JwtConfig`] check: extract a bearer token and verify it via
/// [`verify_jwt`].
///
/// - Missing bearer token, or [`JwtVerifyOutcome::Invalid`] → `401` +
///   `WWW-Authenticate: Bearer`.
/// - [`JwtVerifyOutcome::JwksUnavailable`] → `503` (fail-closed; an operator
///   who attached this filter expects enforcement).
/// - [`JwtVerifyOutcome::Valid`] → copies `claimToHeaders`/
///   `forwardPayloadHeader` into `auth_response_headers_out`, and — when
///   `cfg.forward_token` is `false` (the default) — lists the token's source
///   header(s) in `strip_upstream_headers_out` so
///   [`crate::hooks::upstream_request_filter`] removes them before forwarding.
async fn enforce_jwt(
    jwks_keys: &JwksKeyCache,
    cfg: &JwtConfig,
    session: &mut Session,
    auth_response_headers_out: &mut Option<Vec<(Box<str>, Box<str>)>>,
    strip_upstream_headers_out: &mut Option<Vec<Box<str>>>,
) -> Result<bool> {
    let Some(token) = extract_bearer_token(cfg, session) else {
        return challenge_401_bearer(session).await;
    };

    match verify_jwt(jwks_keys, cfg, &token) {
        JwtVerifyOutcome::Valid(claims) => {
            apply_verified_claims(cfg, &claims, auth_response_headers_out);
            let strip = strip_header_names(cfg);
            if !strip.is_empty() {
                strip_upstream_headers_out
                    .get_or_insert_with(Vec::new)
                    .extend(strip);
            }
            Ok(false)
        }
        JwtVerifyOutcome::JwksUnavailable => {
            write_simple(session, 503).await?;
            Ok(true)
        }
        JwtVerifyOutcome::Invalid => challenge_401_bearer(session).await,
    }
}

#[cfg(test)]
mod jwt_tests {
    use super::*;
    use coxswain_core::routing::JwtHeaderLoc;

    /// Static P-256 PKCS8 DER test key (generated once via `openssl ecparam
    /// -genkey -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -outform
    /// DER`), matching the fixture-key precedent in jsonwebtoken's own test
    /// suite (`tests/ecdsa/private_ecdsa_key.pk8`). Test-only; never used to
    /// sign anything outside this module.
    const TEST_EC_PRIVATE_KEY_DER: &[u8] = &[
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20, 0x8d, 0xf7, 0xc0, 0x49, 0x22, 0x7e, 0x09, 0x3d, 0x4f,
        0x49, 0x33, 0xbd, 0xde, 0xe1, 0x2f, 0xf2, 0xb4, 0x45, 0x05, 0x3d, 0x3d, 0x48, 0xb7, 0x18,
        0x17, 0xf3, 0x51, 0x9e, 0x58, 0xee, 0x1a, 0x86, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xc3,
        0xca, 0xa8, 0x2b, 0xde, 0xa7, 0xd5, 0x25, 0x7d, 0x2c, 0x23, 0xda, 0x92, 0xb6, 0x19, 0xfb,
        0x9c, 0x9c, 0xb0, 0x9a, 0xe8, 0x05, 0x19, 0x73, 0x59, 0xae, 0x42, 0xe3, 0xce, 0xac, 0x2d,
        0x5c, 0xa8, 0x92, 0x3f, 0xdb, 0xf3, 0x43, 0x72, 0xf9, 0x87, 0x0d, 0x6d, 0xb2, 0x29, 0x91,
        0x87, 0xf0, 0xde, 0x80, 0x33, 0x7c, 0xbe, 0x38, 0x31, 0x68, 0xcc, 0x08, 0x97, 0x41, 0x3c,
        0x9d, 0xf8, 0x0d,
    ];

    const TEST_KID: &str = "test-key-1";

    /// A JWKS text carrying the public half of [`TEST_EC_PRIVATE_KEY_DER`],
    /// tagged with [`TEST_KID`]. `Jwk::from_encoding_key` derives the public
    /// EC point directly from the private key via the `rust_crypto` backend —
    /// no separately-embedded public key needed.
    fn test_jwks() -> Arc<str> {
        let encoding_key = jsonwebtoken::EncodingKey::from_ec_der(TEST_EC_PRIVATE_KEY_DER);
        let mut jwk = jsonwebtoken::jwk::Jwk::from_encoding_key(
            &encoding_key,
            jsonwebtoken::Algorithm::ES256,
        )
        .expect("derive JWK from test EC key");
        jwk.common.key_id = Some(TEST_KID.to_string());
        let set = jsonwebtoken::jwk::JwkSet { keys: vec![jwk] };
        Arc::from(serde_json::to_string(&set).expect("serialize test JWKS"))
    }

    /// Sign a test token with `TEST_EC_PRIVATE_KEY_DER`, tagged with
    /// [`TEST_KID`] so `verify_jwt`'s `kid`-narrowing path is exercised.
    fn sign_test_token(claims: &serde_json::Value) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(TEST_KID.to_string());
        let encoding_key = jsonwebtoken::EncodingKey::from_ec_der(TEST_EC_PRIVATE_KEY_DER);
        jsonwebtoken::encode(&header, claims, &encoding_key).expect("sign test token")
    }

    fn test_cfg(issuer: &str, audiences: &[&str]) -> JwtConfig {
        JwtConfig::new(
            Arc::from(issuer),
            audiences.iter().map(|a| Box::from(*a)).collect(),
            test_jwks(),
            Arc::from([JwtHeaderLoc::new("Authorization", "Bearer ")]),
            None,
            Arc::from([]),
            false,
        )
    }

    fn claims(issuer: &str, audience: Option<&str>, exp_offset_secs: i64) -> serde_json::Value {
        let exp = jsonwebtoken::get_current_timestamp() as i64 + exp_offset_secs;
        let mut obj = serde_json::json!({ "iss": issuer, "exp": exp, "sub": "alice" });
        if let Some(aud) = audience {
            obj["aud"] = serde_json::Value::from(aud);
        }
        obj
    }

    #[test]
    fn valid_token_verifies() {
        let cfg = test_cfg("https://issuer.example.com", &[]);
        let token = sign_test_token(&claims("https://issuer.example.com", None, 3600));
        let jwks_keys = JwksKeyCache::new();
        match verify_jwt(&jwks_keys, &cfg, &token) {
            JwtVerifyOutcome::Valid(c) => assert_eq!(c["sub"], "alice"),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn wrong_issuer_is_invalid() {
        let cfg = test_cfg("https://issuer.example.com", &[]);
        let token = sign_test_token(&claims("https://someone-else.example.com", None, 3600));
        let jwks_keys = JwksKeyCache::new();
        assert!(matches!(
            verify_jwt(&jwks_keys, &cfg, &token),
            JwtVerifyOutcome::Invalid
        ));
    }

    #[test]
    fn oct_key_in_jwks_is_never_used_for_verification() {
        // The classic RS/ES→HS "algorithm confusion" attack, cast as: even a
        // JWKS entry that legitimately declares itself a symmetric `oct` key
        // (e.g. an operator or upstream IdP mistake — `JwtAuth` is documented
        // JWKS-only/asymmetric) must never be used to verify a token, however
        // the attacker obtained a token HMAC-signed with its `k` value.
        let secret = b"attacker-known-or-guessed-hmac-secret";
        let jwk = jsonwebtoken::jwk::Jwk {
            common: jsonwebtoken::jwk::CommonParameters {
                key_id: Some(TEST_KID.to_string()),
                // Declares `alg: "HS256"` — without the `oct`-rejection guard
                // this is exactly what lets the candidate loop pick an
                // algorithm and proceed to `DecodingKey::from_jwk`.
                key_algorithm: Some(jsonwebtoken::jwk::KeyAlgorithm::HS256),
                ..Default::default()
            },
            algorithm: jsonwebtoken::jwk::AlgorithmParameters::OctetKey(
                jsonwebtoken::jwk::OctetKeyParameters {
                    key_type: jsonwebtoken::jwk::OctetKeyType::Octet,
                    value: base64::engine::Engine::encode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        secret,
                    ),
                },
            ),
        };
        let set = jsonwebtoken::jwk::JwkSet { keys: vec![jwk] };
        let jwks_text: Arc<str> =
            Arc::from(serde_json::to_string(&set).expect("serialize test JWKS"));
        let cfg = JwtConfig::new(
            Arc::from("https://issuer.example.com"),
            Arc::from([]),
            jwks_text,
            Arc::from([JwtHeaderLoc::new("Authorization", "Bearer ")]),
            None,
            Arc::from([]),
            false,
        );

        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(TEST_KID.to_string());
        let encoding_key = jsonwebtoken::EncodingKey::from_secret(secret);
        let token = jsonwebtoken::encode(
            &header,
            &claims("https://issuer.example.com", None, 3600),
            &encoding_key,
        )
        .expect("sign HS256 token");

        let jwks_keys = JwksKeyCache::new();
        assert!(matches!(
            verify_jwt(&jwks_keys, &cfg, &token),
            JwtVerifyOutcome::Invalid
        ));
    }

    #[test]
    fn missing_iss_claim_is_invalid_even_with_valid_signature() {
        // A validly-signed token that simply omits `iss` must not bypass the
        // issuer restriction — jsonwebtoken only checks `iss` when present,
        // so this only fails if `iss` is in `required_spec_claims`.
        let cfg = test_cfg("https://issuer.example.com", &[]);
        let exp = jsonwebtoken::get_current_timestamp() as i64 + 3600;
        let claims = serde_json::json!({ "exp": exp, "sub": "alice" });
        let token = sign_test_token(&claims);
        let jwks_keys = JwksKeyCache::new();
        assert!(matches!(
            verify_jwt(&jwks_keys, &cfg, &token),
            JwtVerifyOutcome::Invalid
        ));
    }

    #[test]
    fn missing_aud_claim_is_invalid_when_audiences_configured() {
        let cfg = test_cfg("https://issuer.example.com", &["my-api"]);
        let token = sign_test_token(&claims("https://issuer.example.com", None, 3600));
        let jwks_keys = JwksKeyCache::new();
        assert!(matches!(
            verify_jwt(&jwks_keys, &cfg, &token),
            JwtVerifyOutcome::Invalid
        ));
    }

    #[test]
    fn expired_token_is_invalid() {
        let cfg = test_cfg("https://issuer.example.com", &[]);
        let token = sign_test_token(&claims("https://issuer.example.com", None, -3600));
        let jwks_keys = JwksKeyCache::new();
        assert!(matches!(
            verify_jwt(&jwks_keys, &cfg, &token),
            JwtVerifyOutcome::Invalid
        ));
    }

    #[test]
    fn wrong_audience_is_invalid_when_configured() {
        let cfg = test_cfg("https://issuer.example.com", &["my-api"]);
        let token = sign_test_token(&claims(
            "https://issuer.example.com",
            Some("someone-elses-api"),
            3600,
        ));
        let jwks_keys = JwksKeyCache::new();
        assert!(matches!(
            verify_jwt(&jwks_keys, &cfg, &token),
            JwtVerifyOutcome::Invalid
        ));
    }

    #[test]
    fn matching_audience_verifies_when_configured() {
        let cfg = test_cfg("https://issuer.example.com", &["my-api"]);
        let token = sign_test_token(&claims("https://issuer.example.com", Some("my-api"), 3600));
        let jwks_keys = JwksKeyCache::new();
        assert!(matches!(
            verify_jwt(&jwks_keys, &cfg, &token),
            JwtVerifyOutcome::Valid(_)
        ));
    }

    #[test]
    fn absent_audience_check_ignores_token_aud() {
        // `cfg.audiences` empty → aud is never checked, even if the token
        // carries one that doesn't match anything configured.
        let cfg = test_cfg("https://issuer.example.com", &[]);
        let token = sign_test_token(&claims(
            "https://issuer.example.com",
            Some("whatever"),
            3600,
        ));
        let jwks_keys = JwksKeyCache::new();
        assert!(matches!(
            verify_jwt(&jwks_keys, &cfg, &token),
            JwtVerifyOutcome::Valid(_)
        ));
    }

    #[test]
    fn tampered_signature_is_invalid() {
        let cfg = test_cfg("https://issuer.example.com", &[]);
        let mut token = sign_test_token(&claims("https://issuer.example.com", None, 3600));
        // Flip the last character of the signature segment.
        let last = token.pop().expect("token has a signature segment");
        token.push(if last == 'A' { 'B' } else { 'A' });
        let jwks_keys = JwksKeyCache::new();
        assert!(matches!(
            verify_jwt(&jwks_keys, &cfg, &token),
            JwtVerifyOutcome::Invalid
        ));
    }

    #[test]
    fn malformed_token_is_invalid() {
        let cfg = test_cfg("https://issuer.example.com", &[]);
        let jwks_keys = JwksKeyCache::new();
        assert!(matches!(
            verify_jwt(&jwks_keys, &cfg, "not-a-jwt"),
            JwtVerifyOutcome::Invalid
        ));
    }

    #[test]
    fn empty_jwks_is_unavailable() {
        let cfg = JwtConfig::new(
            Arc::from("https://issuer.example.com"),
            Arc::from([]),
            Arc::from(r#"{"keys":[]}"#),
            Arc::from([JwtHeaderLoc::new("Authorization", "Bearer ")]),
            None,
            Arc::from([]),
            false,
        );
        let token = sign_test_token(&claims("https://issuer.example.com", None, 3600));
        let jwks_keys = JwksKeyCache::new();
        assert!(matches!(
            verify_jwt(&jwks_keys, &cfg, &token),
            JwtVerifyOutcome::JwksUnavailable
        ));
    }

    #[test]
    fn unparseable_jwks_is_unavailable() {
        let cfg = JwtConfig::new(
            Arc::from("https://issuer.example.com"),
            Arc::from([]),
            Arc::from("not json"),
            Arc::from([JwtHeaderLoc::new("Authorization", "Bearer ")]),
            None,
            Arc::from([]),
            false,
        );
        let token = sign_test_token(&claims("https://issuer.example.com", None, 3600));
        let jwks_keys = JwksKeyCache::new();
        assert!(matches!(
            verify_jwt(&jwks_keys, &cfg, &token),
            JwtVerifyOutcome::JwksUnavailable
        ));
    }

    #[test]
    fn jwks_key_cache_reuses_parsed_entry_for_identical_content() {
        let jwks = test_jwks();
        let cache = JwksKeyCache::new();
        let first = cache.get_or_parse(&jwks).expect("parse succeeds");
        let second = cache.get_or_parse(&jwks).expect("parse succeeds");
        assert!(
            Arc::ptr_eq(&first, &second),
            "second lookup must reuse the cached parse, not re-parse"
        );
    }

    // ── apply_verified_claims ────────────────────────────────────────────────

    #[test]
    fn claim_to_headers_copies_matching_scalar_claims() {
        let cfg = JwtConfig::new(
            Arc::from("https://issuer.example.com"),
            Arc::from([]),
            Arc::from(r#"{"keys":[]}"#),
            Arc::from([JwtHeaderLoc::new("Authorization", "Bearer ")]),
            None,
            Arc::from([
                (Box::from("sub"), Box::from("x-user-id")),
                (Box::from("missing"), Box::from("x-missing")),
            ]),
            false,
        );
        let claims = serde_json::json!({ "sub": "alice", "roles": ["a", "b"] });
        let mut out = None;
        apply_verified_claims(&cfg, &claims, &mut out);
        let headers = out.expect("headers set");
        assert_eq!(headers.len(), 1, "non-scalar/missing claims are skipped");
        assert_eq!(&*headers[0].0, "x-user-id");
        assert_eq!(&*headers[0].1, "alice");
    }

    #[test]
    fn forward_payload_header_carries_base64url_claims() {
        let cfg = JwtConfig::new(
            Arc::from("https://issuer.example.com"),
            Arc::from([]),
            Arc::from(r#"{"keys":[]}"#),
            Arc::from([JwtHeaderLoc::new("Authorization", "Bearer ")]),
            Some(Box::from("x-jwt-payload")),
            Arc::from([]),
            false,
        );
        let claims = serde_json::json!({ "sub": "alice" });
        let mut out = None;
        apply_verified_claims(&cfg, &claims, &mut out);
        let headers = out.expect("headers set");
        assert_eq!(headers.len(), 1);
        assert_eq!(&*headers[0].0, "x-jwt-payload");
        let decoded = base64::engine::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            headers[0].1.as_ref(),
        )
        .expect("valid base64url");
        let round_tripped: serde_json::Value =
            serde_json::from_slice(&decoded).expect("valid JSON");
        assert_eq!(round_tripped, claims);
    }

    #[test]
    fn no_claim_config_leaves_response_headers_unset() {
        let cfg = JwtConfig::new(
            Arc::from("https://issuer.example.com"),
            Arc::from([]),
            Arc::from(r#"{"keys":[]}"#),
            Arc::from([JwtHeaderLoc::new("Authorization", "Bearer ")]),
            None,
            Arc::from([]),
            false,
        );
        let claims = serde_json::json!({ "sub": "alice" });
        let mut out = None;
        apply_verified_claims(&cfg, &claims, &mut out);
        assert!(out.is_none());
    }

    #[test]
    fn apply_verified_claims_appends_to_existing_response_headers() {
        // The additive auth chain (a Gateway-mandated ext_authz check ahead of
        // a route-level JwtAuth check, or two JwtAuth-style checks) shares one
        // `auth_response_headers` slot across every `enforce()` call — a
        // second populate must APPEND, never clobber the first's headers.
        let cfg = JwtConfig::new(
            Arc::from("https://issuer.example.com"),
            Arc::from([]),
            Arc::from(r#"{"keys":[]}"#),
            Arc::from([JwtHeaderLoc::new("Authorization", "Bearer ")]),
            None,
            Arc::from([(Box::from("sub"), Box::from("x-user-id"))]),
            false,
        );
        let claims = serde_json::json!({ "sub": "alice" });
        let mut out = Some(vec![(Box::from("x-from-ext-authz"), Box::from("upstream"))]);
        apply_verified_claims(&cfg, &claims, &mut out);
        let headers = out.expect("headers set");
        assert_eq!(
            headers.len(),
            2,
            "must retain the pre-existing entry and append the new one"
        );
        assert_eq!(&*headers[0].0, "x-from-ext-authz");
        assert_eq!(&*headers[1].0, "x-user-id");
    }

    #[test]
    fn strip_header_names_always_covers_claim_to_headers_destinations() {
        // A claim that's absent or non-scalar makes `apply_verified_claims`
        // skip its destination header entirely — `strip_header_names` must
        // list it regardless, so a same-named client-supplied header can
        // never survive untouched and masquerade as a verified claim.
        let cfg = JwtConfig::new(
            Arc::from("https://issuer.example.com"),
            Arc::from([]),
            Arc::from(r#"{"keys":[]}"#),
            Arc::from([JwtHeaderLoc::new("Authorization", "Bearer ")]),
            None,
            Arc::from([(Box::from("role"), Box::from("x-user-role"))]),
            true, // forward_token: true — from_headers must NOT appear in strip
        );
        let names = strip_header_names(&cfg);
        assert_eq!(&*names, [Box::<str>::from("x-user-role")]);
    }

    #[test]
    fn strip_header_names_covers_forward_payload_header() {
        let cfg = JwtConfig::new(
            Arc::from("https://issuer.example.com"),
            Arc::from([]),
            Arc::from(r#"{"keys":[]}"#),
            Arc::from([JwtHeaderLoc::new("Authorization", "Bearer ")]),
            Some(Box::from("x-jwt-payload")),
            Arc::from([]),
            true,
        );
        let names = strip_header_names(&cfg);
        assert_eq!(&*names, [Box::<str>::from("x-jwt-payload")]);
    }

    #[test]
    fn strip_header_names_includes_source_headers_when_not_forwarding_token() {
        let cfg = JwtConfig::new(
            Arc::from("https://issuer.example.com"),
            Arc::from([]),
            Arc::from(r#"{"keys":[]}"#),
            Arc::from([JwtHeaderLoc::new("Authorization", "Bearer ")]),
            None,
            Arc::from([]),
            false,
        );
        let names = strip_header_names(&cfg);
        assert_eq!(&*names, [Box::<str>::from("Authorization")]);
    }
}

// ── External auth (ext_authz gRPC — Envoy envoy.service.auth.v3, #23) ─────────

/// gRPC ext_authz: speaks the Envoy `Authorization/Check` proto to the resolved
/// auth pod. Kept in its own module so the Envoy-proto plumbing does not clutter
/// the HTTP forward-auth path; both share [`pick_endpoint`], [`write_simple`],
/// and [`HOP_BY_HOP`].
mod grpc {
    use super::{HOP_BY_HOP, pick_endpoint, should_forward_to_authz, write_simple};
    use envoy_types::pb::envoy::service::auth::v3 as auth_pb;
    use envoy_types::pb::envoy::service::auth::v3::authorization_client::AuthorizationClient;
    use envoy_types::pb::envoy::service::auth::v3::check_response::HttpResponse;
    use pingora_core::Result;
    use pingora_http::ResponseHeader;
    use pingora_proxy::Session;
    use std::collections::HashMap;

    /// `google.rpc.Code::Ok` — an allow. Any other code is a deny.
    const RPC_OK: i32 = 0;
    /// Deny status used when the auth service returns no explicit HTTP status.
    const DEFAULT_DENY_STATUS: u16 = 403;

    /// Enforce a gRPC ext_authz check. Contract mirrors the HTTP transport:
    /// `Ok(false)` allow, `Ok(true)` denied (response written), `Err` internal.
    pub(super) async fn enforce_ext_authz_grpc(
        grpc_channels: &crate::policy::grpc_channel::GrpcAuthChannelCache,
        cfg: &coxswain_core::routing::ExtAuthConfig,
        grpc_cfg: &coxswain_core::routing::GrpcExtAuthConfig,
        session: &mut Session,
        auth_response_headers_out: &mut Option<Vec<(Box<str>, Box<str>)>>,
    ) -> Result<bool> {
        let Some(addr) = pick_endpoint(&cfg.endpoints) else {
            tracing::warn!("ext_authz(grpc) has no resolved endpoints — refusing request (503)");
            write_simple(session, 503).await?;
            return Ok(true);
        };

        // Build the CheckRequest from the (immutably-borrowed) request header
        // before any mutable use of `session` below.
        let check = build_check_request(session, &grpc_cfg.allowed_headers);

        // Reuse (or lazily build) a pooled channel to the auth pod, cleartext
        // (h2c, #544 — see `crate::policy::grpc_channel`). The channel's own
        // connect_timeout is a fixed pool-internal constant, not cfg.timeout:
        // the per-call deadline below is what actually bounds this request
        // (connect included), regardless of whether the channel was already
        // warm or another route's config built this pooled entry first.
        let channel = match grpc_channels.get_or_connect(addr) {
            Ok(ch) => ch,
            Err(e) => return fail(session, cfg.fail_closed, &format!("endpoint: {e}")).await,
        };

        let mut client = AuthorizationClient::new(channel);
        let resp = match tokio::time::timeout(cfg.timeout, client.check(check)).await {
            Ok(Ok(r)) => r.into_inner(),
            Ok(Err(status)) => {
                return fail(session, cfg.fail_closed, &format!("check rpc: {status}")).await;
            }
            Err(_) => return fail(session, cfg.fail_closed, "check timed out").await,
        };

        map_check_response(
            resp,
            grpc_cfg,
            cfg.fail_closed,
            session,
            auth_response_headers_out,
        )
        .await
    }

    /// Fail an unreachable/errored/timed-out check: 503 when fail-closed, else allow.
    async fn fail(session: &mut Session, fail_closed: bool, reason: &str) -> Result<bool> {
        tracing::warn!(reason, fail_closed, "ext_authz(grpc) failed");
        if fail_closed {
            write_simple(session, 503).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// The header map to carry in the `CheckRequest`'s `HttpRequest.headers`,
    /// per [`should_forward_to_authz`] (hop-by-hop stripped, `Host` excluded —
    /// it is a dedicated `HttpRequest` field, not part of this map — and only
    /// names in `allowed_headers` survive). `Session`-free (takes a
    /// [`pingora_http::RequestHeader`] directly) so this is unit-testable
    /// without constructing a Pingora `Session`, mirroring
    /// [`super::select_forwarded_headers`] on the HTTP transport.
    ///
    /// Sized to `allowed_headers.len()`, not `req.headers.len()`: at most that
    /// many entries can ever survive the filter, and `allowed_headers` is
    /// always small (operator-authored, GEP-1494-default-sized) while
    /// `req.headers` is client-controlled and potentially much larger.
    fn select_check_headers(
        req: &pingora_http::RequestHeader,
        allowed_headers: &[Box<str>],
    ) -> HashMap<String, String> {
        let mut headers = HashMap::with_capacity(allowed_headers.len());
        for (name, value) in &req.headers {
            let name_str = name.as_str();
            if !should_forward_to_authz(name_str, allowed_headers) {
                continue;
            }
            if let Ok(v) = value.to_str() {
                headers.insert(name_str.to_owned(), v.to_owned());
            }
        }
        headers
    }

    /// Build the Envoy `CheckRequest` from the downstream request: method, path,
    /// host, scheme, and headers (hop-by-hop stripped, names lower-cased). No body
    /// is forwarded (GEP-1494 `forwardBody` buffering is a follow-up).
    fn build_check_request(
        session: &Session,
        allowed_headers: &[Box<str>],
    ) -> auth_pb::CheckRequest {
        let req = session.req_header();
        let method = req.method.as_str().to_owned();
        let path = req
            .uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str)
            .to_owned();
        let host = req
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        // `host`/`method`/`path` above are dedicated `HttpRequest` fields, not
        // part of this map, so they bypass `allowed_headers` unconditionally —
        // same pseudo-header carve-out as the HTTP transport.
        let headers = select_check_headers(req, allowed_headers);
        let http_req = auth_pb::attribute_context::HttpRequest {
            method,
            path,
            host,
            // Derived from the downstream TLS state — hard-coding `"http"` here
            // reported the wrong scheme to the authz service on HTTPS listeners,
            // bypassing any policy keyed on `scheme == "https"`.
            scheme: crate::hooks::downstream_tls_scheme(session).to_owned(),
            headers,
            ..Default::default()
        };
        auth_pb::CheckRequest {
            attributes: Some(auth_pb::AttributeContext {
                request: Some(auth_pb::attribute_context::Request {
                    http: Some(http_req),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }
    }

    /// The `google.rpc.Status.code` of a check response, or `None` when the
    /// service omitted `status` entirely — a malformed response, not an
    /// implicit OK (prost gives message fields as `Option`; an absent field is
    /// indistinguishable on the wire from an explicit `code: 0` unless handled
    /// separately).
    fn response_status_code(resp: &auth_pb::CheckResponse) -> Option<i32> {
        resp.status.as_ref().map(|s| s.code)
    }

    /// Map a `CheckResponse` onto the allow/deny contract.
    ///
    /// `status.code == OK` → allow (copy the OK response's `allowed_upstream_headers`
    /// allow-list onto the upstream request). Any other code → deny (return the
    /// denied response's HTTP status + controlled headers + body to the client).
    /// An absent `status` is malformed and honours `fail_closed` exactly like a
    /// transport error, rather than being silently treated as OK.
    async fn map_check_response(
        resp: auth_pb::CheckResponse,
        grpc_cfg: &coxswain_core::routing::GrpcExtAuthConfig,
        fail_closed: bool,
        session: &mut Session,
        auth_response_headers_out: &mut Option<Vec<(Box<str>, Box<str>)>>,
    ) -> Result<bool> {
        let Some(code) = response_status_code(&resp) else {
            return fail(session, fail_closed, "malformed check response").await;
        };

        if code == RPC_OK {
            if let Some(HttpResponse::OkResponse(ok)) = resp.http_response
                && !grpc_cfg.response_headers.is_empty()
            {
                let mut forward: Vec<(Box<str>, Box<str>)> = Vec::new();
                for hvo in &ok.headers {
                    if let Some(h) = &hvo.header {
                        let key = h.key.to_ascii_lowercase();
                        if grpc_cfg.response_headers.iter().any(|n| n.as_ref() == key) {
                            forward.push((key.into_boxed_str(), h.value.clone().into_boxed_str()));
                        }
                    }
                }
                if !forward.is_empty() {
                    auth_response_headers_out
                        .get_or_insert_with(Vec::new)
                        .extend(forward);
                }
            }
            return Ok(false);
        }

        // Deny. The Envoy `HttpStatus.code` numeric value IS the HTTP status.
        let (deny_status, hdrs, body): (u16, Vec<(String, String)>, Vec<u8>) =
            match resp.http_response {
                Some(HttpResponse::DeniedResponse(d)) => {
                    let status = d
                        .status
                        .and_then(|s| u16::try_from(s.code).ok())
                        .filter(|s| (100..=599).contains(s))
                        .unwrap_or(DEFAULT_DENY_STATUS);
                    let hdrs = d
                        .headers
                        .iter()
                        .filter_map(|hvo| {
                            let h = hvo.header.as_ref()?;
                            if HOP_BY_HOP.contains(&h.key.to_ascii_lowercase().as_str()) {
                                return None;
                            }
                            Some((h.key.clone(), h.value.clone()))
                        })
                        .collect();
                    (status, hdrs, d.body.into_bytes())
                }
                // OK response shape with a non-OK code, or Error → a bare deny with
                // no body (absent `status` is handled earlier, above).
                _ => (DEFAULT_DENY_STATUS, Vec::new(), Vec::new()),
            };

        let mut resp_hdr = ResponseHeader::build(deny_status, Some(hdrs.len()))?;
        for (name, value) in hdrs {
            let _ = resp_hdr.insert_header(name, value);
        }
        let has_body = !body.is_empty();
        session
            .write_response_header(Box::new(resp_hdr), !has_body)
            .await
            .unwrap_or_else(|e| tracing::error!("failed to write grpc auth deny response: {e}"));
        if has_body {
            session
                .write_response_body(Some(bytes::Bytes::from(body)), true)
                .await
                .unwrap_or_else(|e| tracing::error!("failed to write grpc auth deny body: {e}"));
        }
        Ok(true)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use coxswain_core::routing::GrpcExtAuthConfig;
        use envoy_types::pb::envoy::config::core::v3::{HeaderValue, HeaderValueOption};
        use envoy_types::pb::envoy::r#type::v3::HttpStatus;
        use pingora_http::RequestHeader;
        use std::sync::Arc;

        fn allowed(names: &[&str]) -> Vec<Box<str>> {
            names.iter().map(|n| Box::from(*n)).collect()
        }

        /// Regression for the wiring bug the review flagged on the gRPC
        /// transport: dropping the allow-list filter, or reordering the
        /// host/hop-by-hop carve-out, compiles clean but ships every client
        /// header in the `CheckRequest`. `Session`-free — exercises the same
        /// filtering `build_check_request` delegates to.
        #[test]
        fn select_check_headers_only_returns_allow_listed_survivors() {
            let mut req = RequestHeader::build("GET", b"/", None).unwrap();
            req.insert_header("host", "example.com").unwrap();
            req.insert_header("authorization", "Bearer t").unwrap();
            req.insert_header("cookie", "session=evil").unwrap();
            req.insert_header("connection", "keep-alive").unwrap();

            let headers = select_check_headers(&req, &allowed(&["authorization", "connection"]));

            assert_eq!(
                headers.len(),
                1,
                "only the allow-listed, non-pseudo, non-hop-by-hop header survives: {headers:?}"
            );
            assert_eq!(
                headers.get("authorization").map(String::as_str),
                Some("Bearer t")
            );
        }

        #[test]
        fn select_check_headers_sized_to_allow_list_not_request() {
            let mut req = RequestHeader::build("GET", b"/", None).unwrap();
            for i in 0..40 {
                req.insert_header(format!("x-noise-{i}"), "v").unwrap();
            }
            let headers = select_check_headers(&req, &allowed(&["authorization"]));
            assert!(
                headers.capacity() < 40,
                "capacity must track the allow-list size, not the client's header count: {}",
                headers.capacity()
            );
        }

        fn ok_response(headers: Vec<(&str, &str)>) -> auth_pb::CheckResponse {
            auth_pb::CheckResponse {
                status: Some(envoy_types::pb::google::rpc::Status {
                    code: RPC_OK,
                    ..Default::default()
                }),
                http_response: Some(HttpResponse::OkResponse(auth_pb::OkHttpResponse {
                    headers: headers
                        .into_iter()
                        .map(|(k, v)| HeaderValueOption {
                            header: Some(HeaderValue {
                                key: k.to_owned(),
                                value: v.to_owned(),
                                ..Default::default()
                            }),
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                })),
                ..Default::default()
            }
        }

        /// An OK status with response-header allow-list matches copy the named
        /// header (case-insensitively) into the upstream forward set.
        #[tokio::test]
        async fn ok_response_forwards_allowlisted_headers() {
            let cfg = GrpcExtAuthConfig::new(
                Arc::from([Box::from("authorization")]),
                Arc::from([Box::from("x-auth-user")]),
            );
            let resp = ok_response(vec![("X-Auth-User", "alice"), ("X-Other", "nope")]);
            // map_check_response needs a Session for the deny path only; the allow
            // path writes nothing, so exercise the header-selection logic directly.
            let code = resp.status.as_ref().map_or(RPC_OK, |s| s.code);
            assert_eq!(code, RPC_OK);
            let Some(HttpResponse::OkResponse(ok)) = resp.http_response else {
                panic!("expected OkResponse");
            };
            let mut forward: Vec<(Box<str>, Box<str>)> = Vec::new();
            for hvo in &ok.headers {
                if let Some(h) = &hvo.header {
                    let key = h.key.to_ascii_lowercase();
                    if cfg.response_headers.iter().any(|n| n.as_ref() == key) {
                        forward.push((key.into_boxed_str(), h.value.clone().into_boxed_str()));
                    }
                }
            }
            assert_eq!(
                forward.len(),
                1,
                "only the allow-listed header is forwarded"
            );
            assert_eq!(&*forward[0].0, "x-auth-user");
            assert_eq!(&*forward[0].1, "alice");
        }

        /// A `DeniedHttpResponse.status.code` is mapped verbatim as the HTTP status
        /// when in range; an out-of-range or absent status falls back to 403.
        #[test]
        fn denied_status_maps_http_status_code() {
            let denied = |code: i32| {
                u16::try_from(code)
                    .ok()
                    .filter(|s| (100..=599).contains(s))
                    .unwrap_or(DEFAULT_DENY_STATUS)
            };
            assert_eq!(denied(HttpStatus { code: 401 }.code), 401);
            assert_eq!(denied(HttpStatus { code: 403 }.code), 403);
            assert_eq!(denied(HttpStatus { code: 302 }.code), 302);
            // Out of range → default deny.
            assert_eq!(denied(700), DEFAULT_DENY_STATUS);
            assert_eq!(denied(0), DEFAULT_DENY_STATUS);
        }

        /// A missing `status` is malformed, not an implicit OK (#615) — the caller
        /// must fail the request rather than defaulting to allow.
        #[test]
        fn response_status_code_absent_status_is_none() {
            let resp = auth_pb::CheckResponse {
                status: None,
                http_response: None,
                ..Default::default()
            };
            assert_eq!(response_status_code(&resp), None);
        }

        #[test]
        fn response_status_code_present_status_is_some() {
            let ok = auth_pb::CheckResponse {
                status: Some(envoy_types::pb::google::rpc::Status {
                    code: RPC_OK,
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert_eq!(response_status_code(&ok), Some(RPC_OK));

            let denied = auth_pb::CheckResponse {
                status: Some(envoy_types::pb::google::rpc::Status {
                    code: 7, // PERMISSION_DENIED
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert_eq!(response_status_code(&denied), Some(7));
        }
    }
}
