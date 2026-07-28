//! Wire-DTO conversions.
pub(crate) mod endpoints;
pub(crate) mod health;
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

use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

/// Encode a [`SystemTime`] as Unix seconds for the wire.
///
/// Clamped at both ends rather than fallible: a pre-epoch time reads 0 and a
/// far-future one saturates `i64`. Every wire timestamp is diagnostic (report
/// and ack times shown in the operator UI), so a host with a broken clock
/// should degrade to a nonsense-but-harmless value, not fail the message that
/// carries real state alongside it.
pub(crate) fn system_time_to_unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Inverse of [`system_time_to_unix`], clamping a negative value to the epoch
/// rather than panicking on the subtraction.
pub(crate) fn unix_to_system_time(secs: i64) -> SystemTime {
    u64::try_from(secs)
        .ok()
        .map_or(UNIX_EPOCH, |s| UNIX_EPOCH + Duration::from_secs(s))
}

#[cfg(test)]
mod tests;
