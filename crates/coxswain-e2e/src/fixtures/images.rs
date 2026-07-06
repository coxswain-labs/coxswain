//! Single source of truth for the external container images the e2e fixtures run.
//!
//! Every image is pinned by `tag@sha256:<index-digest>` so a registry tag mutation
//! or a `:latest` re-push can't silently change what a test exercises (rubric #7).
//! The digests are the **multi-arch image-index** digests (not a per-platform
//! manifest), so they match on both arm64 (local OrbStack) and amd64 (CI).
//!
//! These are substituted into fixture YAML via the `${ECHO_IMAGE}`-style tokens by
//! [`apply_fixture`](super::apply_fixture) — fixtures never hardcode an image.
//!
//! To bump an image: resolve the new index digest with
//! `docker buildx imagetools inspect <ref> --format '{{.Manifest.Digest}}'`
//! (or `crane digest <ref>`), then update the constant here. No fixture edits.
//!
//! The intentionally non-resolvable `registry.invalid/...:does-not-exist` image in
//! `gateway_api/cutover_crash_loop.yaml` is deliberately *not* pinned: the test
//! relies on it failing to pull (ImagePullBackOff), so a digest is meaningless.

/// `echo-basic` — the Gateway API conformance echo backend; reflects request
/// metadata so tests can assert which backend served a request.
pub(crate) const ECHO: &str = "gcr.io/k8s-staging-gateway-api/echo-basic:v20260314-v1.5.1@sha256:1930f87f9a037f8acadc37e79185bb217614d9674304e3c1f6074aec8ff6b8dc";

/// `busybox` — used by `slow_echo` for an `nc`/`sleep` upstream that drives
/// request/connect timeout assertions.
pub(crate) const BUSYBOX: &str =
    "busybox:1.37@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028";

/// `jmalloc/echo-server` — WebSocket echo upstream for the passthrough test.
/// Pinned to `0.3.6` (what `:latest` resolved to when pinned) so the tag no
/// longer floats.
pub(crate) const WEBSOCKET_ECHO: &str = "jmalloc/echo-server:0.3.6@sha256:86f2c45aa7e7ebe1be30b21f8cfff25a7ed6e3b059751822d4b35bf244a688d5";

/// `go-httpbin` — a minimal HTTP server that supports `/delay/<seconds>` for
/// load-balance algorithm tests (one fast + one slow upstream, `least_conn`
/// steers more requests to the fast one). Used instead of `busybox` `nc/sleep`
/// because it serves well-formed HTTP/1.1 responses with proper keep-alive.
pub(crate) const GO_HTTPBIN: &str = "ghcr.io/mccutchen/go-httpbin:latest@sha256:90ac1702685468aa592938e65b2ba1b4757e0c006934a962ef7271a8717aaa3b";

/// `pebble` — Let's Encrypt's test ACME server (RFC 8555). Used by the HTTP-01
/// challenge passthrough test: runs in-cluster, validates challenges via the
/// Coxswain proxy, and issues short-lived certificates without a real domain.
///
/// GHCR publishes only `:latest` for Pebble; pinned by index digest so a re-push
/// cannot silently change what the test exercises (rubric #7).
pub(crate) const PEBBLE: &str = "ghcr.io/letsencrypt/pebble:latest@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199";
