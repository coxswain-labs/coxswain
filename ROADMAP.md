# Coxswain — Product Roadmap

## Milestones

Items within each milestone are listed in execution order: each item should be completed before starting the next.

### v0.1 — First Usable Release

The first fully usable version: all must-have features implemented, OCI image published, and Gateway API conformance test suite passing.

- ✅ ~~Basic GitHub Actions CI (fmt, clippy, test) — [#45](https://github.com/coxswain-labs/coxswain/issues/45)~~
- ✅ ~~Cluster-backed integration test harness (`crates/coxswain-e2e`) — [#61](https://github.com/coxswain-labs/coxswain/issues/61)~~
- ✅ ~~IngressClass filtering — [#1](https://github.com/coxswain-labs/coxswain/issues/1)~~
- ✅ ~~`parentRef` matching for HTTPRoute (GEP-724) — [#2](https://github.com/coxswain-labs/coxswain/issues/2)~~
- ✅ ~~`ReferenceGrant` for cross-namespace backends (GEP-709) — [#3](https://github.com/coxswain-labs/coxswain/issues/3)~~
- ✅ ~~Namespace-scoped watch (`--controller-watch-namespace`) — [#4](https://github.com/coxswain-labs/coxswain/issues/4)~~
- ✅ ~~Gateway resource status patching (GEP-1364) — [#5](https://github.com/coxswain-labs/coxswain/issues/5)~~
- ✅ ~~Ingress `.status.loadBalancer` patching — [#48](https://github.com/coxswain-labs/coxswain/issues/48)~~
- ✅ ~~Default backend for Ingress — [#6](https://github.com/coxswain-labs/coxswain/issues/6)~~
- ✅ ~~HTTPRoute header, method, query matching — [#7](https://github.com/coxswain-labs/coxswain/issues/7)~~
- ✅ ~~TLS termination for Ingress (`spec.tls`) — [#8](https://github.com/coxswain-labs/coxswain/issues/8)~~
- ✅ ~~TLS termination for Gateway API listeners (GEP-2907) — [#9](https://github.com/coxswain-labs/coxswain/issues/9)~~
- ✅ ~~Secret watch + hot TLS reload — [#10](https://github.com/coxswain-labs/coxswain/issues/10)~~
- ✅ ~~cert-manager integration (both APIs) — [#11](https://github.com/coxswain-labs/coxswain/issues/11)~~
- ✅ ~~PROXY protocol v1/v2 support — [#49](https://github.com/coxswain-labs/coxswain/issues/49)~~
- ✅ ~~`URLRewrite`, `RequestRedirect`, `RequestHeaderModifier`, `ResponseHeaderModifier` filters (GEP-726, GEP-1323) — [#13](https://github.com/coxswain-labs/coxswain/issues/13)~~
- ✅ ~~HTTPRoute `timeouts` field (GEP-1742) — [#14](https://github.com/coxswain-labs/coxswain/issues/14)~~
- ✅ ~~Non-default redirect status codes in `RequestRedirect` (303, 307, 308) — [#81](https://github.com/coxswain-labs/coxswain/issues/81)~~
- ✅ ~~Support `HTTPRouteRule.name` — named route rules (GEP-995) — [#83](https://github.com/coxswain-labs/coxswain/issues/83)~~
- ✅ ~~Gateway HTTP listener isolation: per-port route scoping — [#84](https://github.com/coxswain-labs/coxswain/issues/84)~~
- ✅ ~~Per-listener Gateway status (`status.listeners`) — [#63](https://github.com/coxswain-labs/coxswain/issues/63)~~
- ✅ ~~Populate `GatewayClass.status.supportedFeatures` (GEP-2162) — [#91](https://github.com/coxswain-labs/coxswain/issues/91)~~
- ✅ ~~Fix `gateway_needs_status_patch` `observedGeneration` comparison (GEP-1364) — [#89](https://github.com/coxswain-labs/coxswain/issues/89)~~
- ✅ ~~Respect `EndpointSlice.conditions.serving` for endpoint drain — [#50](https://github.com/coxswain-labs/coxswain/issues/50)~~
- ✅ ~~Wildcard hostname must match exactly one DNS label — [#100](https://github.com/coxswain-labs/coxswain/issues/100)~~
- ✅ ~~Resolve `Service.port.name` for Ingress backends — [#101](https://github.com/coxswain-labs/coxswain/issues/101)~~
- ✅ ~~Honor `ingressclass.kubernetes.io/is-default-class` annotation — [#102](https://github.com/coxswain-labs/coxswain/issues/102)~~
- ✅ ~~Fix `spec.defaultBackend` semantics: rules-less Ingresses and cross-host fallthrough — [#103](https://github.com/coxswain-labs/coxswain/issues/103)~~
- ✅ ~~Warn instead of silently dropping `Resource`-type Ingress backends — [#104](https://github.com/coxswain-labs/coxswain/issues/104)~~
- ✅ ~~Warn when `spec.tls[].hosts` is empty or omitted — [#105](https://github.com/coxswain-labs/coxswain/issues/105)~~
- ✅ ~~Validate and warn on Ingress paths that do not start with `/`~~ — [#106](https://github.com/coxswain-labs/coxswain/issues/106)
- ✅ ~~Surface `HostRouterBuilder` insert failures as debug log — [#107](https://github.com/coxswain-labs/coxswain/issues/107)~~
- ✅ ~~Dynamic per-port proxy binding (Pingora hot-reload or `--extra-ports` stepping stone) — [#98](https://github.com/coxswain-labs/coxswain/issues/98) _(unblocks `SupportHTTPRouteParentRefPort` and #82)_~~
- ✅ ~~Finish `parentRef.port` traffic-routing path (GEP-957) — [#82](https://github.com/coxswain-labs/coxswain/issues/82)~~
- ✅ ~~Honor `appProtocol` on Service ports for backend protocol selection (GEP-1911) — [#90](https://github.com/coxswain-labs/coxswain/issues/90) _(unlocks `SupportHTTPRouteBackendProtocolH2C` and `SupportHTTPRouteBackendProtocolWebSocket`; supersedes closed #12)_~~
- ✅ ~~Weighted backend refs (`backendRefs[].weight`) — [#17](https://github.com/coxswain-labs/coxswain/issues/17)~~
- ⬜ `BackendTLSPolicy` (GEP-1897) — [#16](https://github.com/coxswain-labs/coxswain/issues/16)
- ⬜ TLS Passthrough for Gateway API listeners (`tls.mode: Passthrough`, GEP-2643) — [#70](https://github.com/coxswain-labs/coxswain/issues/70)
- ⬜ `BackendLBPolicy` (session persistence + timeouts per backend, GEP-1619) — [#15](https://github.com/coxswain-labs/coxswain/issues/15)
- ⬜ `GatewayClass` `ParametersRef` with `CoxswainGatewayClassConfig` CRD — [#38](https://github.com/coxswain-labs/coxswain/issues/38)
- ⬜ `coxswain-labs.dev/*` annotation namespace — [#18](https://github.com/coxswain-labs/coxswain/issues/18)
- ⬜ Ingress annotations for header modifiers + redirects (HTTPRoute filter parity) — [#79](https://github.com/coxswain-labs/coxswain/issues/79)
- ⬜ Nginx-compatible annotation aliases — [#19](https://github.com/coxswain-labs/coxswain/issues/19)
- ⬜ Multi-namespace watch (comma-separated list + label selector) — [#59](https://github.com/coxswain-labs/coxswain/issues/59)
- ⬜ Passive backend health checking — [#22](https://github.com/coxswain-labs/coxswain/issues/22)
- ⬜ Custom per-route Prometheus metrics (latency, rps, errors) — [#20](https://github.com/coxswain-labs/coxswain/issues/20)
- ⬜ Structured per-request access logs — [#21](https://github.com/coxswain-labs/coxswain/issues/21)
- ⬜ `ValidatingAdmissionPolicy` for `coxswain-labs.dev/*` annotations (K8s 1.30+) — [#29](https://github.com/coxswain-labs/coxswain/issues/29)
- ⬜ Dockerfile + OCI image on public registry — [#26](https://github.com/coxswain-labs/coxswain/issues/26)
- ⬜ PodDisruptionBudget + resource requests/limits — [#51](https://github.com/coxswain-labs/coxswain/issues/51)
- ⬜ Helm chart — [#27](https://github.com/coxswain-labs/coxswain/issues/27)
- ⬜ GitHub Actions release pipeline (OCI image, Helm chart, conformance) — [#28](https://github.com/coxswain-labs/coxswain/issues/28)
- ⬜ Sign OCI images with cosign (Sigstore) — [#46](https://github.com/coxswain-labs/coxswain/issues/46)
- ⬜ Docs site (getting started, config reference, architecture) — [#30](https://github.com/coxswain-labs/coxswain/issues/30)
- ⬜ Contributing guide + issue templates — [#31](https://github.com/coxswain-labs/coxswain/issues/31)
- ✅ ~~Full Gateway API conformance test suite — all applicable tests passing — [#34](https://github.com/coxswain-labs/coxswain/issues/34)~~
- ⬜ Conformance badge + stable `coxswain-labs.dev/*` annotation API — [#35](https://github.com/coxswain-labs/coxswain/issues/35)

---

### Refactor fixes (v0.1 code-quality pass)

Work items are listed in execution order; each should be completed and merged before starting the next.

- ✅ ~~`accept.rs` hardening: typed errors, TLS bundle invariant, connection semaphore, shutdown propagation — [#136](https://github.com/coxswain-labs/coxswain/issues/136)~~
- ✅ ~~Propagate typed errors in startup path — [#137](https://github.com/coxswain-labs/coxswain/issues/137)~~
- ✅ ~~Eliminate `appProtocol` string round-trip (GEP-1911 cleanup) — [#138](https://github.com/coxswain-labs/coxswain/issues/138)~~
- ✅ ~~`hot_reload` graceful shutdown via Pingora signal instead of `process::exit` — [#139](https://github.com/coxswain-labs/coxswain/issues/139)~~
- ✅ ~~`#[non_exhaustive]`/`#[must_use]` sweep, `HttpRoute` alias, `BackendPool::next` guard — [#140](https://github.com/coxswain-labs/coxswain/issues/140)~~
- ✅ ~~Cheap perf wins and structural cleanups — [#141](https://github.com/coxswain-labs/coxswain/issues/141)~~
- ✅ ~~Eliminate per-request allocations (deep hot-path pass) — [#142](https://github.com/coxswain-labs/coxswain/issues/142)~~
- ✅ ~~Split large production source files — [#143](https://github.com/coxswain-labs/coxswain/issues/143)~~
- ✅ ~~Split large test modules — [#144](https://github.com/coxswain-labs/coxswain/issues/144)~~
- ⬜ Test-structure alignment and pragmatic coverage gaps — [#159](https://github.com/coxswain-labs/coxswain/issues/159)
- ⬜ E2E harness ergonomics — [#145](https://github.com/coxswain-labs/coxswain/issues/145)
- ⬜ Workspace lint block and Cargo metadata hygiene — [#146](https://github.com/coxswain-labs/coxswain/issues/146)
- ⬜ Workspace-wide `//!` module docs and `///` public item coverage — [#147](https://github.com/coxswain-labs/coxswain/issues/147)

---

### Post-v0.1 — Improvements

- ✅ ~~Per-listener `attachedRoutes` count in `Gateway.status.listeners[]` — [#73](https://github.com/coxswain-labs/coxswain/issues/73)~~
- ⬜ HTTP/2 downstream (h2 ALPN + h2c) — [#32](https://github.com/coxswain-labs/coxswain/issues/32) _(unblocks #33, #96)_
- ⬜ HTTPRoute retry policy (GEP-1731) — [#85](https://github.com/coxswain-labs/coxswain/issues/85)
- ⬜ HTTPRoute retry budgets (GEP-3388) — [#95](https://github.com/coxswain-labs/coxswain/issues/95) _(depends on #85)_
- ⬜ Active backend health probing — [#37](https://github.com/coxswain-labs/coxswain/issues/37) _(depends on #22)_
- ⬜ CORS built-in filter (GEP-1767) — [#41](https://github.com/coxswain-labs/coxswain/issues/41)
- ⬜ Traffic mirroring / shadow traffic (GEP-3171) — [#54](https://github.com/coxswain-labs/coxswain/issues/54) _(depends on #17, #20)_
- ⬜ Canary deployments (progressive weight shifting) — [#53](https://github.com/coxswain-labs/coxswain/issues/53) _(depends on #17, #20)_
- ⬜ Blue/green orchestration — [#55](https://github.com/coxswain-labs/coxswain/issues/55) _(depends on #17, #22)_
- ⬜ `GRPCRoute` + gRPC protocol support (GEP-1016) — [#33](https://github.com/coxswain-labs/coxswain/issues/33) _(depends on #32)_
- ⬜ Frontend client certificate validation / mTLS at Gateway listeners (GEP-91) — [#86](https://github.com/coxswain-labs/coxswain/issues/86)
- ⬜ Backend client certificate / mTLS to upstream pods (GEP-3155) — [#87](https://github.com/coxswain-labs/coxswain/issues/87) _(depends on #16)_
- ⬜ Multi-certificate SNI per listener (GEP-851) — [#72](https://github.com/coxswain-labs/coxswain/issues/72)
- ⬜ Prevent incorrect HTTP/2 connection coalescing on TLS listeners (GEP-3567) — [#96](https://github.com/coxswain-labs/coxswain/issues/96) _(depends on #32)_
- ⬜ ListenerSet resource support (GEP-1713) — [#93](https://github.com/coxswain-labs/coxswain/issues/93)
- ⬜ Per-Gateway Infrastructure (`spec.infrastructure`, GEP-1867) — [#92](https://github.com/coxswain-labs/coxswain/issues/92)
- ⬜ Default Gateways for `parentRef`-less routes (GEP-3793) — [#94](https://github.com/coxswain-labs/coxswain/issues/94)
- ⬜ Backend Resource in `backendRefs` (GEP-4894) — [#97](https://github.com/coxswain-labs/coxswain/issues/97)
- ⬜ OpenTelemetry trace context propagation — [#36](https://github.com/coxswain-labs/coxswain/issues/36)
- ⬜ `SecurityPolicy` (Gateway API ext_authz, GEP-1494) — [#23](https://github.com/coxswain-labs/coxswain/issues/23)
- ⬜ Design trait-based plugin extension architecture — [#56](https://github.com/coxswain-labs/coxswain/issues/56) _(extracted via #23)_
- ⬜ `ext_authz` annotation for Ingress — [#24](https://github.com/coxswain-labs/coxswain/issues/24)
- ⬜ Per-route, per-client rate limiting (both APIs) — [#25](https://github.com/coxswain-labs/coxswain/issues/25)
- ⬜ Implementation-specific extension filters via `ExtensionRef` — [#77](https://github.com/coxswain-labs/coxswain/issues/77)
- ⬜ Session affinity / sticky sessions — [#39](https://github.com/coxswain-labs/coxswain/issues/39) _(depends on #15)_
- ⬜ IPv6 / dual-stack explicit handling — [#42](https://github.com/coxswain-labs/coxswain/issues/42)
- ⬜ Response caching — [#40](https://github.com/coxswain-labs/coxswain/issues/40)
- ⬜ Performance profiling on admin port — [#43](https://github.com/coxswain-labs/coxswain/issues/43)
- ⬜ Dry-run mode for controller — [#44](https://github.com/coxswain-labs/coxswain/issues/44)
