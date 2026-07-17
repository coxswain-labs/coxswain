# Builds the coxswain-scheme-authz e2e fixture image (#620): a minimal gRPC
# ext_authz server that ALLOWS a request iff the CheckRequest reports
# `attributes.request.http.scheme == "https"`, else denies. Exercises the fix
# for the previously hard-coded `scheme: "http"` in coxswain-proxy's gRPC
# CheckRequest. Local-only fixture — never pushed to a registry, loaded into
# the test cluster by the e2e harness (see
# crates/coxswain-e2e/src/harness/bootstrap.rs).
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /scheme-authz .

FROM scratch
COPY --from=builder /scheme-authz /scheme-authz
EXPOSE 9000
ENTRYPOINT ["/scheme-authz"]
