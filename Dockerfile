# syntax=docker/dockerfile:1.7

# Multi-stage build for coxswain.
#
# Stage 0 (ui-builder): compile the Vite + Preact operator UI into a single
#                       self-contained dist/index.html that the Rust build
#                       embeds at compile time via include_str!.
# Stage 1 (planner):   generate a cargo-chef recipe for the dependency tree.
# Stage 2 (builder):   cook deps into a cached layer (BoringSSL builds here,
#                      ~5-10 min on amd64) then compile the coxswain binary.
# Stage 3 (runtime):   copy the binary onto distroless/cc-debian13:nonroot.
#
# BoringSSL (vendored by pingora's boring-sys) is the dominant build cost.
# cargo-chef caches it in the deps layer so PR rebuilds that don't touch
# Cargo.lock skip recompiling it entirely.

# Node 24 (Active LTS) — matches the CI workflows' setup-node and satisfies
# Vite 8's engine requirement (^20.19 || >=22.12).
FROM node:24-alpine AS ui-builder
WORKDIR /app
COPY ui/package.json ui/package-lock.json ./ui/
RUN cd ui && npm ci
COPY ui/ ./ui/
RUN cd ui && npm run build

FROM --platform=$BUILDPLATFORM lukemathwalker/cargo-chef:latest-rust-bookworm AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# BoringSSL build dependencies: cmake (CMake-based build), golang (BoringSSL
# uses Go to generate assembly), perl (asm code generators), clang +
# libclang-dev (bindgen FFI bindings). build-essential and pkg-config come
# from the chef base but are listed for clarity.
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        golang \
        perl \
        clang \
        libclang-dev \
        pkg-config \
        build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY --from=planner /app/recipe.json recipe.json
# Cook only the deps reachable from the coxswain bin — skips the coxswain-e2e
# dependency tree. Heaviest cached layer; invalidates on Cargo.lock changes only.
ARG CARGO_BUILD_JOBS
RUN cargo chef cook --release --recipe-path recipe.json --bin coxswain \
    $([ -n "$CARGO_BUILD_JOBS" ] && echo "--jobs $CARGO_BUILD_JOBS")
COPY . .
# Inject the pre-built UI so the include_str! in coxswain-admin resolves.
COPY --from=ui-builder /app/ui/dist ./ui/dist
RUN cargo build --release --bin coxswain \
    $([ -n "$CARGO_BUILD_JOBS" ] && echo "--jobs $CARGO_BUILD_JOBS")

FROM gcr.io/distroless/cc-debian13:nonroot AS runtime
COPY --from=builder /app/target/release/coxswain /usr/local/bin/coxswain

# Static OCI image-spec annotations. Dynamic ones (created, revision, version,
# ref.name) are added at build time by docker/metadata-action in CI.
# org.opencontainers.image.source is load-bearing: ghcr.io uses it to auto-link
# the package to the source repository.
LABEL org.opencontainers.image.title="coxswain" \
      org.opencontainers.image.description="A pure-Rust Kubernetes Ingress & Gateway API Controller built on Pingora" \
      org.opencontainers.image.url="https://github.com/coxswain-labs/coxswain" \
      org.opencontainers.image.source="https://github.com/coxswain-labs/coxswain" \
      org.opencontainers.image.documentation="https://github.com/coxswain-labs/coxswain" \
      org.opencontainers.image.vendor="Coxswain Labs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="Matteo Giaccone" \
      org.opencontainers.image.base.name="gcr.io/distroless/cc-debian13:nonroot"

# Defaults; the binary already defaults --log to "info" via clap so this is
# primarily for discoverability via `docker inspect`.
ENV COXSWAIN_LOG=info \
    COXSWAIN_LOG_FORMAT=json

# No EXPOSE — coxswain's port model is fully env-driven. Only the health
# (8081) and admin (8082) ports have defaults; proxy 80/443 are off unless
# COXSWAIN_INGRESS_HTTP_PORT / _HTTPS_PORT are set. EXPOSE 80 443 would imply
# a contract the bare image doesn't honor. README's `## Ports (default)`
# table is the canonical documentation.

# No CMD: every production deployment picks a role explicitly
# (`serve controller`, `serve proxy --shared`, etc.). The Helm chart and the
# raw manifests both set `args:` on the Deployment; bare `docker run` errors
# with clap's help message, matching the binary's "no implicit role" stance.
# Local development uses `cargo run -- serve dev` from a working copy, not
# the image, so we don't need a dev-default CMD either.
ENTRYPOINT ["/usr/local/bin/coxswain"]
