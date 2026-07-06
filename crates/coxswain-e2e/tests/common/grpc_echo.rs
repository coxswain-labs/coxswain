//! Minimal prost message types for the GrpcEcho conformance service.
//!
//! Service: `gateway_api_conformance.echo_basic.grpcecho.GrpcEcho`. Derived by
//! hand from `grpcecho.proto` — avoids a `prost-build` dependency. Shared by
//! `routing.rs` and `observability.rs`, both of which drive gRPC calls through
//! `backends::GRPC_ECHO`.

#[derive(Clone, PartialEq, prost::Message)]
pub struct EchoRequest {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GrpcContext {
    #[prost(string, tag = "4")]
    pub pod: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct EchoAssertions {
    #[prost(message, optional, tag = "4")]
    pub context: Option<GrpcContext>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct EchoResponse {
    #[prost(message, optional, tag = "1")]
    pub assertions: Option<EchoAssertions>,
}
