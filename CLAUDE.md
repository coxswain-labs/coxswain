# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

**Coxswain** is a pure-Rust Kubernetes Ingress & Gateway API controller backed by [Pingora](https://github.com/cloudflare/pingora) as the proxy engine. It watches Kubernetes `Ingress` and `Gateway API` resources and dynamically routes traffic without a full reload.

## Commands

```bash
# Build all crates
cargo build

# Build release
cargo build --release

# Run all tests
cargo test

# Run tests for a single crate
cargo test -p coxswain-core

# Run a single test by name
cargo test -p coxswain-core test_name

# Check (no codegen, fast)
cargo check

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt

# Run the binary
cargo run --bin coxswain
```

## Architecture

The workspace has four crates with a strict dependency order:

```
coxswain-bin
  ├── coxswain-controller
  │     └── coxswain-core
  └── coxswain-proxy
        └── coxswain-core
```

### `coxswain-core`
Shared types and the routing table. Uses `arc-swap` for lock-free atomic swaps of the route config (allowing the controller and proxy to share state without locks) and `matchit` for radix-tree URL matching. This is the only crate that both `coxswain-controller` and `coxswain-proxy` depend on.

### `coxswain-controller`
Kubernetes controller that reconciles `Ingress` and Gateway API (`HTTPRoute`, etc.) resources. Uses `kube` for the controller runtime (watches + reconcilers) and `k8s-openapi`/`gateway-api` for typed API objects. When resources change, it writes updated route config into the `arc-swap` store owned by `coxswain-core`.

### `coxswain-proxy`
Pingora-based reverse proxy. Reads routing decisions from the `coxswain-core` store and forwards requests to upstream Kubernetes services. Uses `pingora-proxy` for the HTTP proxy layer and `tracing` for structured logging.

### `coxswain-bin`
Entry point only — wires the controller and proxy together and starts the Tokio runtime.

## Key design pattern

The controller and proxy communicate through an `ArcSwap<RoutingTable>` defined in `coxswain-core`. The controller holds a write handle and swaps in a new table on every reconcile; the proxy holds a read handle and does a cheap load on every request. There are no channels or locks on the hot path.
