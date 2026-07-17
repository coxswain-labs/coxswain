# Builds the coxswain-malformed-authz e2e fixture image (#615): a minimal
# gRPC server that answers every check with a zero-length response body,
# exercising coxswain-proxy's "absent status" ext_authz fail_closed path.
# Local-only fixture — never pushed to a registry, loaded into the test
# cluster by the e2e harness (see crates/coxswain-e2e/src/harness/bootstrap.rs).
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /malformed-authz .

FROM scratch
COPY --from=builder /malformed-authz /malformed-authz
EXPOSE 9000
ENTRYPOINT ["/malformed-authz"]
