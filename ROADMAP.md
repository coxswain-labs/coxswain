# Coxswain — Product Roadmap

## Milestones

Items within each milestone are listed in execution order: each item should be completed before starting the next.

### v0.1 — First Release

First publishable, installable release. Gateway API conformant (33/33 core + 29/29 declared extended); basic Ingress support spec-complete; distributed as a signed OCI image and Helm chart with installation docs. Feature-enhancement work moved to v0.2.

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
- ✅ ~~`BackendTLSPolicy` (GEP-1897) — [#16](https://github.com/coxswain-labs/coxswain/issues/16)~~
- ✅ ~~Per-backend `HTTPRoute` filters (`backendRefs[].filters`) — [#167](https://github.com/coxswain-labs/coxswain/issues/167) _(unlocks `SupportHTTPRouteBackendRequestHeaderModification`)_~~
- ✅ ~~Declare `SupportReferenceGrant` in `opts.SupportedFeatures` — [#166](https://github.com/coxswain-labs/coxswain/issues/166) _(implementation already complete in `coxswain-core::reference_grants`; this is a paperwork claim)_~~
- ✅ ~~Full Gateway API conformance test suite — all applicable tests passing — [#34](https://github.com/coxswain-labs/coxswain/issues/34)~~
- ✅ ~~Code-quality pass: `accept.rs` hardening (typed errors, TLS bundle invariant, connection semaphore, shutdown propagation) — [#136](https://github.com/coxswain-labs/coxswain/issues/136)~~
- ✅ ~~Code-quality pass: propagate typed errors in startup path — [#137](https://github.com/coxswain-labs/coxswain/issues/137)~~
- ✅ ~~Code-quality pass: eliminate `appProtocol` string round-trip (GEP-1911 cleanup) — [#138](https://github.com/coxswain-labs/coxswain/issues/138)~~
- ✅ ~~Code-quality pass: `hot_reload` graceful shutdown via Pingora signal instead of `process::exit` — [#139](https://github.com/coxswain-labs/coxswain/issues/139)~~
- ✅ ~~Code-quality pass: `#[non_exhaustive]`/`#[must_use]` sweep, `HttpRoute` alias, `BackendPool::next` guard — [#140](https://github.com/coxswain-labs/coxswain/issues/140)~~
- ✅ ~~Code-quality pass: cheap perf wins and structural cleanups — [#141](https://github.com/coxswain-labs/coxswain/issues/141)~~
- ✅ ~~Code-quality pass: eliminate per-request allocations (deep hot-path pass) — [#142](https://github.com/coxswain-labs/coxswain/issues/142)~~
- ✅ ~~Code-quality pass: split large production source files — [#143](https://github.com/coxswain-labs/coxswain/issues/143)~~
- ✅ ~~Code-quality pass: split large test modules — [#144](https://github.com/coxswain-labs/coxswain/issues/144)~~
- ✅ ~~Code-quality pass: test-structure alignment and pragmatic coverage gaps — [#159](https://github.com/coxswain-labs/coxswain/issues/159)~~
- ✅ ~~Code-quality pass: E2E harness ergonomics — [#145](https://github.com/coxswain-labs/coxswain/issues/145)~~
- ✅ ~~Code-quality pass: workspace lint block and Cargo metadata hygiene — [#146](https://github.com/coxswain-labs/coxswain/issues/146)~~
- ✅ ~~Code-quality pass: workspace-wide `//!` module docs and `///` public item coverage — [#147](https://github.com/coxswain-labs/coxswain/issues/147)~~
- ⬜ Gate `synced`/`readyz` on Ingress `InitDone` in addition to HTTPRoute — [#158](https://github.com/coxswain-labs/coxswain/issues/158) _(bug: readyz can flip before Ingress sync completes)_
- ⬜ Dockerfile + OCI image on public registry — [#26](https://github.com/coxswain-labs/coxswain/issues/26)
- ⬜ PodDisruptionBudget + resource requests/limits — [#51](https://github.com/coxswain-labs/coxswain/issues/51)
- ⬜ Helm chart — [#27](https://github.com/coxswain-labs/coxswain/issues/27)
- ⬜ GitHub Actions release pipeline (OCI image, Helm chart, conformance) — [#28](https://github.com/coxswain-labs/coxswain/issues/28)
- ⬜ Sign OCI images with cosign (Sigstore) — [#46](https://github.com/coxswain-labs/coxswain/issues/46)
- ⬜ Docs site (getting started, config reference, architecture) — [#30](https://github.com/coxswain-labs/coxswain/issues/30)
- ⬜ Contributing guide + issue templates — [#31](https://github.com/coxswain-labs/coxswain/issues/31)
- ⬜ Conformance badge + stable `coxswain-labs.dev/*` annotation API — [#35](https://github.com/coxswain-labs/coxswain/issues/35)

---

### v0.2 — Feature Complete

Feature parity with mature ingress controllers. Closes the extended Gateway API conformance ratchet, adds the Ingress value-add annotation surface (and the nginx-compat aliases that let users migrate without rewriting manifests), and ships the operator UX expected of a production controller (per-route metrics, access logs, passive health, multi-namespace watch, `ValidatingAdmissionPolicy` for the annotation surface).

Extended Gateway API conformance ratchet:

- ⬜ `BackendTLSPolicy` `subjectAltNames` validation — [#133](https://github.com/coxswain-labs/coxswain/issues/133) _(unlocks `SupportBackendTLSPolicySANValidation`; depends on #16)_
- ⬜ HTTP/2 downstream (h2 ALPN + h2c prior knowledge) — [#32](https://github.com/coxswain-labs/coxswain/issues/32) _(unlocks `SupportHTTPRouteBackendProtocolH2C`; also unblocks backlog #33 GRPCRoute and #96 H/2 coalescing)_

Gateway API extras:

- ⬜ TLS Passthrough for Gateway API listeners (`tls.mode: Passthrough`, GEP-2643) — [#70](https://github.com/coxswain-labs/coxswain/issues/70)
- ⬜ `BackendLBPolicy` (session persistence + timeouts per backend, GEP-1619) — [#15](https://github.com/coxswain-labs/coxswain/issues/15)
- ⬜ `GatewayClass` `ParametersRef` with `CoxswainGatewayClassConfig` CRD — [#38](https://github.com/coxswain-labs/coxswain/issues/38)

Ingress value-adds (spec-equivalent annotation surface):

- ⬜ `coxswain-labs.dev/*` annotation namespace (timeouts, retries, rewrites) — [#18](https://github.com/coxswain-labs/coxswain/issues/18)
- ⬜ Ingress annotations for header modifiers + redirects (HTTPRoute filter parity) — [#79](https://github.com/coxswain-labs/coxswain/issues/79)
- ⬜ Nginx-compatible annotation aliases for migration — [#19](https://github.com/coxswain-labs/coxswain/issues/19)
- ⬜ `ValidatingAdmissionPolicy` for `coxswain-labs.dev/*` annotations (K8s 1.30+) — [#29](https://github.com/coxswain-labs/coxswain/issues/29) _(depends on #18, #79)_

Operator UX:

- ⬜ Multi-namespace watch (comma-separated list + label selector) — [#59](https://github.com/coxswain-labs/coxswain/issues/59)
- ⬜ Passive backend health checking — [#22](https://github.com/coxswain-labs/coxswain/issues/22)
- ⬜ Custom per-route Prometheus metrics (latency, rps, errors) — [#20](https://github.com/coxswain-labs/coxswain/issues/20)
- ⬜ Structured per-request access logs — [#21](https://github.com/coxswain-labs/coxswain/issues/21)

---

## Backlog

Future / community-driven work. Items here have no GitHub milestone assignment and carry the `status: backlog` label; promotion to a v0.N milestone happens when scope solidifies. Grouped by theme — items within a theme are not strictly ordered (dependencies are annotated inline).

Gateway API resources and extras:

- ⬜ `GRPCRoute` + gRPC protocol support (GEP-1016) — [#33](https://github.com/coxswain-labs/coxswain/issues/33) _(depends on #32)_
- ⬜ ListenerSet resource support (GEP-1713) — [#93](https://github.com/coxswain-labs/coxswain/issues/93)
- ⬜ Per-Gateway Infrastructure (`spec.infrastructure`, GEP-1867) — [#92](https://github.com/coxswain-labs/coxswain/issues/92)
- ⬜ Default Gateways for `parentRef`-less routes (GEP-3793) — [#94](https://github.com/coxswain-labs/coxswain/issues/94)
- ⬜ Backend Resource in `backendRefs` (GEP-4894) — [#97](https://github.com/coxswain-labs/coxswain/issues/97)
- ⬜ Prevent incorrect HTTP/2 connection coalescing on TLS listeners (GEP-3567) — [#96](https://github.com/coxswain-labs/coxswain/issues/96) _(depends on #32)_

Traffic management:

- ⬜ HTTPRoute retry policy (GEP-1731) — [#85](https://github.com/coxswain-labs/coxswain/issues/85)
- ⬜ HTTPRoute retry budgets (GEP-3388) — [#95](https://github.com/coxswain-labs/coxswain/issues/95) _(depends on #85)_
- ⬜ Traffic mirroring / shadow traffic (GEP-3171) — [#54](https://github.com/coxswain-labs/coxswain/issues/54) _(depends on #17, #20)_
- ⬜ Canary deployments (progressive weight shifting) — [#53](https://github.com/coxswain-labs/coxswain/issues/53) _(depends on #17, #20)_
- ⬜ Blue/green orchestration — [#55](https://github.com/coxswain-labs/coxswain/issues/55) _(depends on #17, #22)_
- ⬜ Session affinity / sticky sessions — [#39](https://github.com/coxswain-labs/coxswain/issues/39) _(depends on #15)_
- ⬜ Response caching — [#40](https://github.com/coxswain-labs/coxswain/issues/40)

TLS / mTLS:

- ⬜ Frontend client certificate validation / mTLS at Gateway listeners (GEP-91) — [#86](https://github.com/coxswain-labs/coxswain/issues/86)
- ⬜ Backend client certificate / mTLS to upstream pods (GEP-3155) — [#87](https://github.com/coxswain-labs/coxswain/issues/87) _(depends on #16)_
- ⬜ Multi-certificate SNI per listener (GEP-851) — [#72](https://github.com/coxswain-labs/coxswain/issues/72)

Auth and security:

- ⬜ `SecurityPolicy` (Gateway API ext_authz, GEP-1494) — [#23](https://github.com/coxswain-labs/coxswain/issues/23)
- ⬜ `ext_authz` annotation for Ingress — [#24](https://github.com/coxswain-labs/coxswain/issues/24)
- ⬜ Per-route, per-client rate limiting (both APIs) — [#25](https://github.com/coxswain-labs/coxswain/issues/25)

Filters and extensibility:

- ⬜ CORS built-in filter (GEP-1767) — [#41](https://github.com/coxswain-labs/coxswain/issues/41)
- ⬜ Implementation-specific extension filters via `ExtensionRef` — [#77](https://github.com/coxswain-labs/coxswain/issues/77)
- ⬜ Design trait-based plugin extension architecture — [#56](https://github.com/coxswain-labs/coxswain/issues/56) _(extracted via #23)_

Observability:

- ✅ ~~Per-listener `attachedRoutes` count in `Gateway.status.listeners[]` — [#73](https://github.com/coxswain-labs/coxswain/issues/73)~~
- ⬜ Active backend health probing — [#37](https://github.com/coxswain-labs/coxswain/issues/37) _(depends on #22)_
- ⬜ OpenTelemetry trace context propagation — [#36](https://github.com/coxswain-labs/coxswain/issues/36)

Operations:

- ⬜ IPv6 / dual-stack explicit handling — [#42](https://github.com/coxswain-labs/coxswain/issues/42)
- ⬜ Performance profiling on admin port — [#43](https://github.com/coxswain-labs/coxswain/issues/43)
- ⬜ Dry-run mode for controller — [#44](https://github.com/coxswain-labs/coxswain/issues/44)
