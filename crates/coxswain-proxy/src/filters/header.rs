//! Header-modifier mechanics shared by the request and response filter paths:
//! the `RequestHeaderModifier` / `ResponseHeaderModifier` application
//! ([`apply_header_mod`]) and the proxy-owned forwarding-header deny-list that
//! gates operator re-injection on the request path (#409, #410).

use coxswain_core::routing::HeaderMod;
use http::{HeaderName, HeaderValue};
use pingora_http::{RequestHeader, ResponseHeader};

/// Headers the proxy unconditionally owns on every upstream request.
///
/// The proxy strips whatever the downstream client sent and, when PROXY-protocol
/// is active, replaces `Forwarded` with a proxy-generated value derived from the
/// real client address.  Route operators must also not re-inject these headers via
/// `RequestHeaderModifier` filters — `apply_header_mod` skips `set`/`add` operations
/// for any name in this list when called on the request path (#409, #410).
///
/// Never extend this list with headers the proxy does not itself set;
/// strip-without-replace is the safe default for unknown infrastructure headers.
pub(crate) static CLIENT_FORWARDING_HEADERS: std::sync::LazyLock<[http::HeaderName; 4]> =
    std::sync::LazyLock::new(|| {
        [
            http::HeaderName::from_static("forwarded"),
            http::HeaderName::from_static("x-forwarded-for"),
            http::HeaderName::from_static("x-forwarded-proto"),
            http::HeaderName::from_static("x-real-ip"),
        ]
    });

/// Returns `true` when `name` is a proxy-owned forwarding header that neither
/// clients nor route operators may inject.
///
/// Used by [`apply_header_mod`] to gate `set`/`add` operations on the request
/// path — the `remove` operation is always allowed.
pub(crate) fn is_owned_forwarding_header(name: &http::HeaderName) -> bool {
    CLIENT_FORWARDING_HEADERS.iter().any(|h| h == name)
}

pub(crate) trait HeaderTarget {
    fn hdr_set(&mut self, name: HeaderName, value: HeaderValue);
    fn hdr_add(&mut self, name: HeaderName, value: HeaderValue);
    fn hdr_remove(&mut self, name: &HeaderName);
}

impl HeaderTarget for RequestHeader {
    fn hdr_set(&mut self, name: HeaderName, value: HeaderValue) {
        let _ = self.insert_header(name, value);
    }
    fn hdr_add(&mut self, name: HeaderName, value: HeaderValue) {
        let _ = self.append_header(name, value);
    }
    fn hdr_remove(&mut self, name: &HeaderName) {
        self.remove_header(name);
    }
}

impl HeaderTarget for ResponseHeader {
    fn hdr_set(&mut self, name: HeaderName, value: HeaderValue) {
        let _ = self.insert_header(name, value);
    }
    fn hdr_add(&mut self, name: HeaderName, value: HeaderValue) {
        let _ = self.append_header(name, value);
    }
    fn hdr_remove(&mut self, name: &HeaderName) {
        self.remove_header(name);
    }
}

/// Apply a [`HeaderMod`] to `target`, skipping `set`/`add` entries for which
/// `skip` returns `true`.
///
/// On the **request path** pass [`is_owned_forwarding_header`] as `skip` so that
/// route operators cannot re-inject proxy-owned forwarding headers after the
/// client-strip step (#409, #410).  On the **response path** pass `|_| false`.
///
/// The `remove` loop is never gated — silently removing a blocked header is
/// harmless and prevents stale values reaching the backend.
pub(crate) fn apply_header_mod<H: HeaderTarget>(
    target: &mut H,
    m: &HeaderMod,
    skip: impl Fn(&http::HeaderName) -> bool,
) {
    for (name, value) in &m.set {
        if !skip(name) {
            target.hdr_set(name.clone(), value.clone());
        }
    }
    for (name, value) in &m.add {
        if !skip(name) {
            target.hdr_add(name.clone(), value.clone());
        }
    }
    for name in &m.remove {
        target.hdr_remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_header_mod, is_owned_forwarding_header};
    use coxswain_core::routing::HeaderMod;
    use pingora_http::{RequestHeader, ResponseHeader};

    fn req() -> RequestHeader {
        let mut r = RequestHeader::build("GET", b"/original/path?q=1", None).unwrap();
        r.insert_header("x-keep", "yes").unwrap();
        r
    }

    fn resp() -> ResponseHeader {
        ResponseHeader::build(200, None).unwrap()
    }

    fn hmod(add: &[(&str, &str)], set: &[(&str, &str)], remove: &[&str]) -> HeaderMod {
        HeaderMod::parse(add, set, remove).unwrap()
    }

    #[test]
    fn request_header_set_overwrites() {
        let mut r = req();
        let m = hmod(&[], &[("x-keep", "overwritten")], &[]);
        apply_header_mod(&mut r, &m, |_| false);
        assert_eq!(r.headers.get("x-keep").unwrap(), "overwritten");
    }

    #[test]
    fn request_header_add_appends() {
        let mut r = req();
        let m = hmod(&[("x-keep", "extra")], &[], &[]);
        apply_header_mod(&mut r, &m, |_| false);
        let vals: Vec<_> = r.headers.get_all("x-keep").iter().collect();
        assert_eq!(vals.len(), 2);
    }

    #[test]
    fn request_header_remove() {
        let mut r = req();
        let m = hmod(&[], &[], &["x-keep"]);
        apply_header_mod(&mut r, &m, |_| false);
        assert!(r.headers.get("x-keep").is_none());
    }

    #[test]
    fn response_header_set_overwrites() {
        let mut r = resp();
        r.insert_header("x-old", "old").unwrap();
        let m = hmod(&[], &[("x-old", "new")], &[]);
        apply_header_mod(&mut r, &m, |_| false);
        assert_eq!(r.headers.get("x-old").unwrap(), "new");
    }

    #[test]
    fn response_header_add_appends() {
        let mut r = resp();
        r.insert_header("x-multi", "a").unwrap();
        let m = hmod(&[("x-multi", "b")], &[], &[]);
        apply_header_mod(&mut r, &m, |_| false);
        let vals: Vec<_> = r.headers.get_all("x-multi").iter().collect();
        assert_eq!(vals.len(), 2);
    }

    #[test]
    fn is_owned_forwarding_header_recognises_all_four() {
        for name in &[
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-real-ip",
        ] {
            let h = http::HeaderName::from_bytes(name.as_bytes()).unwrap();
            assert!(
                is_owned_forwarding_header(&h),
                "{name} must be recognised as a proxy-owned header (#410)"
            );
        }
    }

    #[test]
    fn is_owned_forwarding_header_allows_custom_headers() {
        for name in &["x-team-id", "x-request-id", "x-proxy-engine"] {
            let h = http::HeaderName::from_bytes(name.as_bytes()).unwrap();
            assert!(
                !is_owned_forwarding_header(&h),
                "{name} must NOT be treated as a proxy-owned header (#410)"
            );
        }
    }
}
