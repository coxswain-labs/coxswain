# Coxswain

A Kubernetes Ingress and Gateway API controller written in Rust, backed by [Pingora](https://github.com/cloudflare/pingora) — Cloudflare's battle-tested proxy library.

!!! success "Gateway API conformant"
    Coxswain passes the full Gateway API standard conformance suite across **v1.4–v1.6** (standard channel).

!!! info "Pre-1.0 — ready to try"
    Ingress and Gateway API support is feature-complete. We're hardening toward 1.0, and broad real-world testing is what gets us there — run it against your workloads and [open an issue](https://github.com/coxswain-labs/coxswain/issues) for anything you hit. It hasn't been battle-tested at scale yet, so validate before you rely on it in production. Early adopters and contributors welcome.

## Overview

- **One fleet, every protocol** — classic `Ingress` and Gateway API `HTTPRoute`, `GRPCRoute`, `TLSRoute`, `TCPRoute`, `UDPRoute`, and `ListenerSet`, L7 and L4, served by a single proxy fleet.
- **Live updates, no restarts** — routing changes and TLS certificate rotations take effect without restarting the proxy or dropping connections.
- **Zero cluster access on the data plane** — proxy pods hold no Kubernetes API credentials, so a compromised proxy can neither read nor write the cluster.
- **Mistakes caught at admission** — a rich `ingress.coxswain-labs.dev/*` annotation surface, validated by `ValidatingAdmissionPolicy` before a bad config ever reaches the proxy.
- **Runs on your cluster's Gateway API** — v1.4 through v1.6 (standard channel), detecting each release's kinds and features at runtime; no version pin.

## Get started

New to Coxswain? The walkthrough installs it and routes your first request in a few minutes.

[Get started →](getting-started.md){ .md-button .md-button--primary }

