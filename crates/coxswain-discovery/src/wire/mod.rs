//! Wire-DTO conversions.
pub(crate) mod endpoints;
pub mod listener_status;
pub mod resource;
pub mod routing;
pub mod scope;
pub mod tls;

pub use listener_status::*;
pub use resource::*;
pub use routing::*;
pub use scope::*;
pub use tls::*;

use crate::error::WireError;

/// Narrow a `u32` wire scalar to `u16`, rejecting values that exceed the
/// target domain instead of truncating them (`as u16` silently aliases
/// `65616` to `80`).
///
/// The sole sanctioned entry point for decoding a wire port, HTTP status
/// code, or backend weight — every such field originated as a `u16` promoted
/// to `u32` for the wire, so an out-of-range value can only mean protocol
/// confusion, not a legitimate large value.
///
/// # Errors
///
/// Returns [`WireError::ValueOutOfRange`] if `raw` exceeds `u16::MAX`.
pub(crate) fn narrow_u16(raw: u32, field: &'static str) -> Result<u16, WireError> {
    u16::try_from(raw).map_err(|_| WireError::ValueOutOfRange { field, value: raw })
}

#[cfg(test)]
mod tests;
