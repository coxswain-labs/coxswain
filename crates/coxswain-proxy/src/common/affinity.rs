//! Session-affinity (sticky-session) resolution helpers for the proxy hot path (#15).
//!
//! Stateless by design: cookie mode encodes the pinned endpoint's token directly in a
//! server-injected cookie, and header mode rendezvous-hashes a request header's value
//! over the live endpoint set. There is no server-side session map — affinity is
//! naturally per-process and re-establishes itself whenever a pinned endpoint is gone.
//! The selection logic and the stable token/hash functions live in
//! [`coxswain_core::routing`]; this module only bridges request headers to them.

use coxswain_core::routing::{BackendGroup, SessionAffinity, affinity_hash, affinity_token};
use pingora_http::{RequestHeader, ResponseHeader};
use std::net::SocketAddr;

/// Outcome of resolving session affinity for one request.
pub(crate) struct AffinityDecision {
    /// Endpoint to pin to, or `None` to fall through to weighted round-robin.
    pub pin: Option<SocketAddr>,
    /// Whether the response must emit a fresh affinity `Set-Cookie` (cookie mode, no
    /// valid cookie presented). Always `false` in header mode.
    pub set_cookie: bool,
}

/// Resolve the affinity pin for `req` against `group`'s configured affinity.
///
/// - No affinity → `(None, false)`.
/// - Cookie mode: a valid, live cookie pins (no re-issue); an absent or stale cookie
///   yields no pin but requests a fresh `Set-Cookie` so round-robin's choice is pinned.
/// - Header mode: the header value rendezvous-hashes to an endpoint; an absent header
///   yields plain round-robin and never a cookie.
pub(crate) fn resolve(req: &RequestHeader, group: &BackendGroup) -> AffinityDecision {
    match group.session_affinity() {
        None => AffinityDecision {
            pin: None,
            set_cookie: false,
        },
        Some(SessionAffinity::Cookie { cookie_name }) => {
            let pinned = cookie_value(req, cookie_name)
                .and_then(|raw| u64::from_str_radix(raw, 16).ok())
                .and_then(|token| group.endpoint_by_token(token));
            match pinned {
                Some((addr, _)) => AffinityDecision {
                    pin: Some(addr),
                    set_cookie: false,
                },
                // Absent or stale (pod removed) → re-establish on this request.
                None => AffinityDecision {
                    pin: None,
                    set_cookie: true,
                },
            }
        }
        Some(SessionAffinity::Header { header }) => {
            let pin = req
                .headers
                .get(header)
                .map(|v| affinity_hash(v.as_bytes()))
                .and_then(|key| group.endpoint_by_hash(key))
                .map(|(addr, _)| addr);
            AffinityDecision {
                pin,
                set_cookie: false,
            }
        }
        // `SessionAffinity` is non-exhaustive; a future mode the proxy doesn't yet
        // understand degrades safely to round-robin.
        Some(_) => AffinityDecision {
            pin: None,
            set_cookie: false,
        },
    }
}

/// Inject the affinity `Set-Cookie` for the chosen `addr` under `cookie_name`.
///
/// Value is `hex(affinity_token(addr))`; attributes are `Path=/; HttpOnly` (a session
/// cookie — no `Max-Age`, since the annotation surface defines no lifetime). This is
/// the one intentional owned-string allocation in cookie mode, emitted only when a
/// fresh pin was established.
///
/// # Errors
/// Propagates Pingora's header-insertion error if the assembled value is rejected
/// (not expected: `cookie_name` is validated to an RFC 6265 token at parse time and
/// the token is hex).
pub(crate) fn inject_set_cookie(
    resp: &mut ResponseHeader,
    cookie_name: &str,
    addr: SocketAddr,
) -> pingora_core::Result<()> {
    use std::fmt::Write;
    let mut value = String::with_capacity(cookie_name.len() + 32);
    let _ = write!(
        value,
        "{cookie_name}={token:x}; Path=/; HttpOnly",
        token = affinity_token(addr)
    );
    resp.insert_header(http::header::SET_COOKIE, value)
}

/// Read the value of cookie `name` from the request's `Cookie` header.
///
/// Returns the first match. Cookie syntax is `name=value` pairs separated by `"; "`
/// (RFC 6265 §5.4); names are case-sensitive. No allocation — returns a borrow into
/// the header value.
fn cookie_value<'a>(req: &'a RequestHeader, name: &str) -> Option<&'a str> {
    let raw = req.headers.get(http::header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k.trim() == name).then(|| v.trim())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::routing::SessionAffinity;
    use std::sync::Arc;

    fn cookie_group(addrs: &[&str]) -> BackendGroup {
        let parsed: Vec<SocketAddr> = addrs.iter().map(|a| a.parse().unwrap()).collect();
        BackendGroup::new("ns/svc".to_string(), parsed).with_session_affinity(Some(
            SessionAffinity::Cookie {
                cookie_name: Arc::from("__coxswain_session"),
            },
        ))
    }

    fn req_with(headers: &[(http::HeaderName, &str)]) -> RequestHeader {
        let mut r = RequestHeader::build("GET", b"/", None).unwrap();
        for (name, value) in headers {
            r.insert_header(name.clone(), *value).unwrap();
        }
        r
    }

    #[test]
    fn no_affinity_yields_no_pin() {
        let group = BackendGroup::new("ns/svc".to_string(), vec!["10.0.0.1:80".parse().unwrap()]);
        let d = resolve(&req_with(&[]), &group);
        assert!(d.pin.is_none() && !d.set_cookie);
    }

    #[test]
    fn cookie_absent_requests_fresh_cookie() {
        let group = cookie_group(&["10.0.0.1:80", "10.0.0.2:80"]);
        let d = resolve(&req_with(&[]), &group);
        assert!(d.pin.is_none(), "no cookie → no pin");
        assert!(d.set_cookie, "no cookie → must set a fresh one");
    }

    #[test]
    fn valid_cookie_pins_without_reissue() {
        let group = cookie_group(&["10.0.0.1:80", "10.0.0.2:80"]);
        let target: SocketAddr = "10.0.0.2:80".parse().unwrap();
        let token = affinity_token(target);
        let cookie = format!("__coxswain_session={token:x}");
        let d = resolve(&req_with(&[(http::header::COOKIE, &cookie)]), &group);
        assert_eq!(d.pin, Some(target));
        assert!(!d.set_cookie, "a valid pin is not re-issued");
    }

    #[test]
    fn stale_cookie_falls_back_and_reissues() {
        let group = cookie_group(&["10.0.0.1:80", "10.0.0.2:80"]);
        let gone: SocketAddr = "10.0.0.9:80".parse().unwrap();
        let cookie = format!("__coxswain_session={:x}", affinity_token(gone));
        let d = resolve(&req_with(&[(http::header::COOKIE, &cookie)]), &group);
        assert!(d.pin.is_none(), "stale token → no pin");
        assert!(d.set_cookie, "stale token → re-establish affinity");
    }

    #[test]
    fn cookie_value_found_among_several() {
        let req = req_with(&[(
            http::header::COOKIE,
            "a=1; __coxswain_session=deadbeef; b=2",
        )]);
        assert_eq!(cookie_value(&req, "__coxswain_session"), Some("deadbeef"));
        assert_eq!(cookie_value(&req, "missing"), None);
    }

    #[test]
    fn header_value_pins_consistently() {
        let parsed: Vec<SocketAddr> = ["10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let group = BackendGroup::new("ns/svc".to_string(), parsed).with_session_affinity(Some(
            SessionAffinity::Header {
                header: http::HeaderName::from_static("x-session-id"),
            },
        ));
        let h = http::HeaderName::from_static("x-session-id");
        let first = resolve(&req_with(&[(h.clone(), "user-42")]), &group).pin;
        assert!(first.is_some());
        assert_eq!(
            resolve(&req_with(&[(h, "user-42")]), &group).pin,
            first,
            "same header value pins to the same endpoint"
        );
    }

    #[test]
    fn header_absent_is_round_robin_no_cookie() {
        let parsed: Vec<SocketAddr> = vec!["10.0.0.1:80".parse().unwrap()];
        let group = BackendGroup::new("ns/svc".to_string(), parsed).with_session_affinity(Some(
            SessionAffinity::Header {
                header: http::HeaderName::from_static("x-session-id"),
            },
        ));
        let d = resolve(&req_with(&[]), &group);
        assert!(d.pin.is_none() && !d.set_cookie);
    }
}
