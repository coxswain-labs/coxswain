//! Re-exports Gateway API types from the active channel.
//!
//! Default (release): `gateway_api::apis::standard`
//! With `--features experimental`: `gateway_api::apis::experimental`
//!
//! Import as `use crate::gw_types::v::...` instead of hard-coding the channel
//! path. When adding a new alpha resource guarded by the experimental channel,
//! gate the call site with `#[cfg(feature = "experimental")]`.

#[cfg(not(feature = "experimental"))]
pub use gateway_api::apis::standard as v;

#[cfg(feature = "experimental")]
pub use gateway_api::apis::experimental as v;
