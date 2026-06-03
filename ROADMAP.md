# Coxswain — Product Roadmap

## Milestones

Items within each milestone are listed in recommended implementation sequence.

### v0.1 — First Usable Release

The first fully usable version: all MUST-have features implemented, OCI image published, and Gateway API conformance test suite passing. Themes below reflect recommended implementation order.

#### Multi-tenancy & Spec Correctness

The most critical correctness gaps. Without these, Coxswain is unsafe in any shared cluster and fails Gateway API conformance on basic tests.

- [x] ~~Basic GitHub Actions CI (fmt, clippy, test) — [#45](https://github.com/coxswain-labs/coxswain/issues/45) `MUST`~~
- [x] ~~Cluster-backed integration test harness (`crates/coxswain-e2e`) — [#61](https://github.com/coxswain-labs/coxswain/issues/61) `SHOULD`~~
- [x] ~~IngressClass filtering — [#1](https://github.com/coxswain-labs/coxswain/issues/1) `MUST`~~
- [x] ~~`parentRef` matching for HTTPRoute (GEP-724) — [#2](https://github.com/coxswain-labs/coxswain/issues/2) `MUST`~~
- [x] ~~`ReferenceGrant` for cross-namespace backends (GEP-709) — [#3](https://github.com/coxswain-labs/coxswain/issues/3) `MUST`~~
- [x] ~~Namespace-scoped watch (`--controller-watch-namespace`) — [#4](https://github.com/coxswain-labs/coxswain/issues/4) `MUST`~~
- [ ] Multi-namespace watch (comma-separated list + label selector) — [#59](https://github.com/coxswain-labs/coxswain/issues/59) `SHOULD`
- [x] ~~Gateway resource status patching (GEP-1364) — [#5](https://github.com/coxswain-labs/coxswain/issues/5) `MUST`~~
- [x] ~~Ingress `.status.loadBalancer` patching — [#48](https://github.com/coxswain-labs/coxswain/issues/48) `MUST`~~
- [x] ~~Default backend for Ingress — [#6](https://github.com/coxswain-labs/coxswain/issues/6) `MUST`~~
- [x] ~~HTTPRoute header, method, query matching — [#7](https://github.com/coxswain-labs/coxswain/issues/7) `MUST`~~
- [ ] Honor `parentRef.port` in HTTPRoute (GEP-957) — [#82](https://github.com/coxswain-labs/coxswain/issues/82) `MUST` _(controller validation done; traffic routing blocked by #98)_
- [x] ~~Support `HTTPRouteRule.name` — named route rules (GEP-995) — [#83](https://github.com/coxswain-labs/coxswain/issues/83) `MUST`~~
- [x] ~~Gateway HTTP listener isolation: per-port route scoping — [#84](https://github.com/coxswain-labs/coxswain/issues/84) `MUST`~~
- [x] ~~Per-listener Gateway status (`status.listeners`) — [#63](https://github.com/coxswain-labs/coxswain/issues/63) `SHOULD`~~
- [ ] Fix `gateway_needs_status_patch` `observedGeneration` comparison (GEP-1364) — [#89](https://github.com/coxswain-labs/coxswain/issues/89) `SHOULD`
- [ ] Populate `GatewayClass.status.supportedFeatures` (GEP-2162) — [#91](https://github.com/coxswain-labs/coxswain/issues/91) `MUST`

#### TLS & WebSocket

TLS is a launch blocker. WebSocket and protocol negotiation are the minimum needed to support real-time workloads.

- [x] ~~TLS termination for Ingress (`spec.tls`) — [#8](https://github.com/coxswain-labs/coxswain/issues/8) `MUST`~~
- [x] ~~TLS termination for Gateway API listeners (GEP-2907) — [#9](https://github.com/coxswain-labs/coxswain/issues/9) `MUST`~~
- [x] ~~Secret watch + hot TLS reload — [#10](https://github.com/coxswain-labs/coxswain/issues/10) `MUST`~~
- [x] ~~cert-manager integration (both APIs) — [#11](https://github.com/coxswain-labs/coxswain/issues/11) `MUST`~~
- [ ] WebSocket upgrade passthrough — [#12](https://github.com/coxswain-labs/coxswain/issues/12) `MUST` _(superseded by #90 once implemented)_
- [x] ~~PROXY protocol v1/v2 support — [#49](https://github.com/coxswain-labs/coxswain/issues/49) `MUST`~~
- [ ] TLS Passthrough for Gateway API listeners (`tls.mode: Passthrough`, GEP-2643) — [#70](https://github.com/coxswain-labs/coxswain/issues/70) `MUST`
- [ ] Honor `appProtocol` on Service ports for backend protocol selection (GEP-1911) — [#90](https://github.com/coxswain-labs/coxswain/issues/90) `SHOULD` _(supersedes #12)_

#### Traffic Management

Full HTTPRoute filter compliance + the annotation layer for Ingress.

- [x] ~~`URLRewrite`, `RequestRedirect`, `RequestHeaderModifier`, `ResponseHeaderModifier` filters (GEP-726, GEP-1323) — [#13](https://github.com/coxswain-labs/coxswain/issues/13) `MUST`~~
- [x] ~~HTTPRoute `timeouts` field (GEP-1742) — [#14](https://github.com/coxswain-labs/coxswain/issues/14) `MUST`~~
- [x] ~~Non-default redirect status codes in `RequestRedirect` (303, 307, 308) — [#81](https://github.com/coxswain-labs/coxswain/issues/81) `SHOULD`~~
- [ ] `BackendLBPolicy` (session persistence + timeouts per backend, GEP-1619) — [#15](https://github.com/coxswain-labs/coxswain/issues/15) `MUST`
- [ ] `BackendTLSPolicy` (GEP-1897) — [#16](https://github.com/coxswain-labs/coxswain/issues/16) `MUST`
- [ ] Weighted backend refs (`backendRefs[].weight`) — [#17](https://github.com/coxswain-labs/coxswain/issues/17) `MUST`
- [ ] `GatewayClass` `ParametersRef` with `CoxswainGatewayClassConfig` CRD — [#38](https://github.com/coxswain-labs/coxswain/issues/38) `SHOULD`
- [ ] `coxswain-labs.dev/*` annotation namespace — [#18](https://github.com/coxswain-labs/coxswain/issues/18) `MUST`
- [ ] Ingress annotations for header modifiers + redirects (HTTPRoute filter parity) — [#79](https://github.com/coxswain-labs/coxswain/issues/79) `MUST`
- [ ] Nginx-compatible annotation aliases — [#19](https://github.com/coxswain-labs/coxswain/issues/19) `MUST`

#### Observability & Health

Operators need signals before they trust any controller in production.

- [ ] Custom per-route Prometheus metrics (latency, rps, errors) — [#20](https://github.com/coxswain-labs/coxswain/issues/20) `MUST`
- [ ] Structured per-request access logs — [#21](https://github.com/coxswain-labs/coxswain/issues/21) `MUST`
- [ ] Passive backend health checking — [#22](https://github.com/coxswain-labs/coxswain/issues/22) `MUST`
- [ ] Endpoint drain (`conditions.serving`) — [#50](https://github.com/coxswain-labs/coxswain/issues/50) `MUST`

#### Security & Policy

Auth and rate limiting close the gap with production-grade controllers.

- [ ] `SecurityPolicy` (Gateway API ext_authz, GEP-1494) — [#23](https://github.com/coxswain-labs/coxswain/issues/23) `MUST`
- [ ] `ext_authz` annotation for Ingress — [#24](https://github.com/coxswain-labs/coxswain/issues/24) `MUST`
- [ ] Per-route, per-client rate limiting (both APIs) — [#25](https://github.com/coxswain-labs/coxswain/issues/25) `MUST`

#### Distribution & Community

Makes Coxswain installable and opens the door for community contributions.

- [ ] Dockerfile + OCI image on public registry — [#26](https://github.com/coxswain-labs/coxswain/issues/26) `MUST`
- [ ] Helm chart — [#27](https://github.com/coxswain-labs/coxswain/issues/27) `MUST`
- [ ] PodDisruptionBudget + resource requests/limits — [#51](https://github.com/coxswain-labs/coxswain/issues/51) `MUST`
- [ ] GitHub Actions release pipeline (OCI image, Helm chart, conformance) — [#28](https://github.com/coxswain-labs/coxswain/issues/28) `MUST`
- [ ] Sign OCI images with cosign (Sigstore) — [#46](https://github.com/coxswain-labs/coxswain/issues/46) `MUST`
- [ ] `ValidatingAdmissionPolicy` (K8s 1.30+) — [#29](https://github.com/coxswain-labs/coxswain/issues/29) `MUST`
- [ ] Docs site (getting started, config reference, architecture) — [#30](https://github.com/coxswain-labs/coxswain/issues/30) `MUST`
- [ ] Contributing guide + issue templates — [#31](https://github.com/coxswain-labs/coxswain/issues/31) `MUST`
- [ ] Design trait-based plugin extension architecture — [#56](https://github.com/coxswain-labs/coxswain/issues/56) `SHOULD`

**Community opens for contributions at this milestone.**

#### Conformance

The final gate: all applicable Gateway API conformance tests passing, badge published, and annotation API declared stable.

- [ ] Full Gateway API conformance test suite — all applicable tests passing — [#34](https://github.com/coxswain-labs/coxswain/issues/34) `MUST`
- [ ] Conformance badge + stable `coxswain-labs.dev/*` annotation API — [#35](https://github.com/coxswain-labs/coxswain/issues/35) `MUST`

---

### Post-v0.1 — Improvements

#### MUST

- [ ] HTTP/2 downstream (h2 ALPN + h2c) — [#32](https://github.com/coxswain-labs/coxswain/issues/32)
- [ ] Honor `listener.port` for per-port TLS/HTTP bind sockets — [#98](https://github.com/coxswain-labs/coxswain/issues/98) `MUST` _(unblocks `SupportHTTPRouteParentRefPort` and #82; requires Pingora graceful hot-reload)_
- [ ] Multi-certificate SNI per listener (GEP-851) — [#72](https://github.com/coxswain-labs/coxswain/issues/72)
- [ ] Frontend client certificate validation / mTLS at Gateway listeners (GEP-91) — [#86](https://github.com/coxswain-labs/coxswain/issues/86)
- [ ] Backend client certificate / mTLS to upstream pods (GEP-3155) — [#87](https://github.com/coxswain-labs/coxswain/issues/87)
- [ ] HTTPRoute retry policy (GEP-1731) — [#85](https://github.com/coxswain-labs/coxswain/issues/85)
- [ ] ListenerSet resource support (GEP-1713) — [#93](https://github.com/coxswain-labs/coxswain/issues/93)

#### SHOULD

- [ ] `GRPCRoute` + gRPC protocol support (GEP-1016) — [#33](https://github.com/coxswain-labs/coxswain/issues/33)
- [x] ~~Per-listener `attachedRoutes` count in `Gateway.status.listeners[]` — [#73](https://github.com/coxswain-labs/coxswain/issues/73)~~
- [ ] Implementation-specific extension filters via `ExtensionRef` — [#77](https://github.com/coxswain-labs/coxswain/issues/77)
- [ ] OpenTelemetry trace context propagation — [#36](https://github.com/coxswain-labs/coxswain/issues/36)
- [ ] Active backend health probing — [#37](https://github.com/coxswain-labs/coxswain/issues/37)
- [ ] Canary deployments (progressive weight shifting) — [#53](https://github.com/coxswain-labs/coxswain/issues/53)
- [ ] Traffic mirroring / shadow traffic (GEP-3171) — [#54](https://github.com/coxswain-labs/coxswain/issues/54)
- [ ] Per-Gateway Infrastructure (`spec.infrastructure`, GEP-1867) — [#92](https://github.com/coxswain-labs/coxswain/issues/92)
- [ ] Default Gateways for `parentRef`-less routes (GEP-3793) — [#94](https://github.com/coxswain-labs/coxswain/issues/94)
- [ ] HTTPRoute retry budgets (GEP-3388) — [#95](https://github.com/coxswain-labs/coxswain/issues/95)
- [ ] Prevent incorrect HTTP/2 connection coalescing on TLS listeners (GEP-3567) — [#96](https://github.com/coxswain-labs/coxswain/issues/96)

#### NICE

- [ ] Session affinity / sticky sessions — [#39](https://github.com/coxswain-labs/coxswain/issues/39)
- [ ] Response caching — [#40](https://github.com/coxswain-labs/coxswain/issues/40)
- [ ] CORS built-in filter (GEP-1767) — [#41](https://github.com/coxswain-labs/coxswain/issues/41)
- [ ] IPv6 / dual-stack explicit handling — [#42](https://github.com/coxswain-labs/coxswain/issues/42)
- [ ] Performance profiling on admin port — [#43](https://github.com/coxswain-labs/coxswain/issues/43)
- [ ] Dry-run mode for controller — [#44](https://github.com/coxswain-labs/coxswain/issues/44)
- [ ] Blue/green orchestration — [#55](https://github.com/coxswain-labs/coxswain/issues/55)
- [ ] Backend Resource in `backendRefs` (GEP-4894) — [#97](https://github.com/coxswain-labs/coxswain/issues/97)
