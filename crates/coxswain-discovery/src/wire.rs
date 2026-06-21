//! Wire-DTO types: serialisable representations of routing snapshots.
//!
//! The controller serialises compiled routing tables into a wire DTO here, and
//! the proxy deserialises the DTO back into builder inputs that feed the existing
//! `IngressRoutingTableBuilder` / `GatewayRoutingTableBuilder`. Implementation
//! lands in T2 (#238).
