//! GEP-2257-compliant Duration type for Gateway API
//!
//! `gateway_api_types::Duration` is a duration type where parsing and
//! formatting obey GEP-2257. It is based on `std::time::Duration` and uses
//! `kube::core::Duration` for the heavy lifting of parsing.
//!
//! GEP-2257 defines a duration format for the Gateway API that is based on
//! Go's `time.ParseDuration`, with additional restrictions: negative
//! durations, units smaller than millisecond, and floating point are not
//! allowed, and durations are limited to four components of no more than five
//! digits each. See <https://gateway-api.sigs.k8s.io/geps/gep-2257> for the
//! complete specification.
//!
//! Ported from the upstream `gateway-api` crate (`coxswain-labs/gateway-api-rs`)
//! this crate replaces (#510); actively consumed by
//! `coxswain-reflector::gateway_api::timeouts::parse_gateway_duration` for
//! HTTPRoute `timeouts` fields — strict GEP-2257 validation there is a
//! correctness tightening over the previous ad hoc parser.

use std::{fmt, str::FromStr, sync::LazyLock, time::Duration as StdDuration};

use kube::core::Duration as K8sDuration;
use regex::Regex;

/// GEP-2257-compliant Duration type for Gateway API
///
/// See <https://gateway-api.sigs.k8s.io/geps/gep-2257> for the complete
/// specification.
///
/// Per GEP-2257, when parsing a `gateway_api_types::Duration` from a string,
/// the string must match
///
/// `^([0-9]{1,5}(h|m|s|ms)){1,4}$`
///
/// and is otherwise parsed the same way that Go's `time.ParseDuration` parses
/// durations. When formatting a `gateway_api_types::Duration` as a string,
/// zero-valued durations must always be formatted as `0s`, and non-zero
/// durations must be formatted with only one instance of each applicable
/// unit, greatest unit first.
///
/// The rules above imply that `gateway_api_types::Duration` cannot represent
/// negative durations, durations with sub-millisecond precision, or durations
/// larger than 99999h59m59s999ms. Since there's no meaningful way in Rust to
/// allow string formatting to fail, these conditions are checked instead when
/// instantiating `gateway_api_types::Duration`.
#[non_exhaustive]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Duration(StdDuration);

/// Regex pattern defining valid GEP-2257 Duration strings.
const GEP2257_PATTERN: &str = r"^([0-9]{1,5}(h|m|s|ms)){1,4}$";

/// Maximum duration that can be represented by GEP-2257, in milliseconds.
const MAX_DURATION_MS: u128 = (((99999 * 3600) + (59 * 60) + 59) * 1_000) + 999;

/// `MAX_DURATION_MS` as `u64` (safe: the value fits in 37 bits).
#[cfg(test)]
const MAX_DURATION_MS_U64: u64 = MAX_DURATION_MS as u64;

/// Checks if a duration is valid according to GEP-2257. If it's not, returns
/// an error explaining why.
///
/// # Errors
///
/// Returns `Err` if `duration` has sub-millisecond precision or exceeds the
/// GEP-2257 maximum of `99999h59m59s999ms`.
#[must_use = "check the Result — a dropped Err silently accepts an invalid duration"]
pub fn is_valid(duration: StdDuration) -> Result<(), String> {
    if !duration.subsec_nanos().is_multiple_of(1_000_000) {
        return Err("Cannot express sub-millisecond precision in GEP-2257".to_string());
    }
    if duration.as_millis() > MAX_DURATION_MS {
        return Err("Duration exceeds GEP-2257 maximum 99999h59m59s999ms".to_string());
    }
    Ok(())
}

impl TryFrom<StdDuration> for Duration {
    type Error = String;

    fn try_from(duration: StdDuration) -> Result<Self, Self::Error> {
        is_valid(duration)?;
        Ok(Duration(duration))
    }
}

impl TryFrom<K8sDuration> for Duration {
    type Error = String;

    fn try_from(duration: K8sDuration) -> Result<Self, Self::Error> {
        if duration.is_negative() {
            return Err("Duration cannot be negative".to_string());
        }
        let stddur = StdDuration::from(duration);
        is_valid(stddur)?;
        Ok(Duration(stddur))
    }
}

/// Converting a validated `gateway_api_types::Duration` back to
/// `std::time::Duration` can never fail — every `Duration` value was already
/// checked at construction.
impl From<Duration> for StdDuration {
    fn from(duration: Duration) -> Self {
        duration.0
    }
}

impl Duration {
    /// Creates a new `gateway_api_types::Duration` from seconds and
    /// nanoseconds, requiring the result to be valid per GEP-2257.
    ///
    /// # Errors
    ///
    /// Returns `Err` per [`is_valid`].
    #[must_use = "check the Result — a dropped Err discards the GEP-2257 validation failure"]
    pub fn new(secs: u64, nanos: u32) -> Result<Self, String> {
        let stddur = StdDuration::new(secs, nanos);
        is_valid(stddur)?;
        Ok(Self(stddur))
    }

    /// Creates a new `gateway_api_types::Duration` from seconds.
    ///
    /// # Errors
    ///
    /// Returns `Err` per [`is_valid`].
    #[must_use = "check the Result — a dropped Err discards the GEP-2257 validation failure"]
    pub fn from_secs(secs: u64) -> Result<Self, String> {
        Self::new(secs, 0)
    }

    /// Creates a new `gateway_api_types::Duration` from microseconds.
    ///
    /// # Errors
    ///
    /// Returns `Err` per [`is_valid`].
    #[must_use = "check the Result — a dropped Err discards the GEP-2257 validation failure"]
    pub fn from_micros(micros: u64) -> Result<Self, String> {
        let sec = micros / 1_000_000;
        // Safe: (micros % 1_000_000) * 1_000 maxes at 999_999_000, fits in u32.
        // (clippy::cast_possible_truncation is pedantic-tier and off by default;
        // this crate doesn't opt into the pedantic group, so no attribute needed.)
        let ns = ((micros % 1_000_000) * 1_000) as u32;
        Self::new(sec, ns)
    }

    /// Creates a new `gateway_api_types::Duration` from milliseconds.
    ///
    /// # Errors
    ///
    /// Returns `Err` per [`is_valid`].
    #[must_use = "check the Result — a dropped Err discards the GEP-2257 validation failure"]
    pub fn from_millis(millis: u64) -> Result<Self, String> {
        let sec = millis / 1_000;
        // Safe: (millis % 1_000) * 1_000_000 maxes at 999_000_000, fits in u32.
        let ns = ((millis % 1_000) * 1_000_000) as u32;
        Self::new(sec, ns)
    }

    /// The number of whole seconds in the entire duration.
    #[must_use]
    pub fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }

    /// The number of milliseconds in the whole duration. GEP-2257 doesn't
    /// support sub-millisecond precision, so this is always exact.
    #[must_use]
    pub fn as_millis(&self) -> u128 {
        self.0.as_millis()
    }

    /// The number of nanoseconds in the whole duration. Always exact.
    #[must_use]
    pub fn as_nanos(&self) -> u128 {
        self.0.as_nanos()
    }

    /// The number of nanoseconds in the part of the duration that's not whole
    /// seconds. Since GEP-2257 doesn't support sub-millisecond precision,
    /// this is always 0 or a multiple of 1,000,000.
    #[must_use]
    pub fn subsec_nanos(&self) -> u32 {
        self.0.subsec_nanos()
    }

    /// Whether the duration is zero. Per GEP-2257, callers treat a zero
    /// duration as "unset".
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

/// Parsing a `gateway_api_types::Duration` from a string requires that the
/// input string obey GEP-2257.
impl FromStr for Duration {
    type Err = String;

    fn from_str(duration_str: &str) -> Result<Self, Self::Err> {
        static RE: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(GEP2257_PATTERN).unwrap_or_else(|e| {
                // Unreachable except by a bug in the compile-time-constant
                // pattern literal above — nothing runtime-reachable can flip
                // this regex from valid to invalid. Still surfaces as a data,
                // not a control-flow, panic to satisfy this workspace's
                // `expect_used`/`unwrap_used = deny` gate.
                panic!("GEP2257 regex {GEP2257_PATTERN:?} did not compile: {e}")
            })
        });

        if !RE.is_match(duration_str) {
            return Err("Invalid duration format".to_string());
        }

        match K8sDuration::from_str(duration_str) {
            Err(err) => Err(err.to_string()),
            Ok(kd) => Duration::try_from(kd),
        }
    }
}

/// Formatting a `gateway_api_types::Duration` for display, following the
/// GEP-2257 rules: zero is always `"0s"`; non-zero durations use only one
/// instance of each applicable unit, greatest unit first.
impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return write!(f, "0s");
        }

        let ms = self.subsec_nanos() / 1_000_000;
        let mut secs = self.as_secs();

        let hours = secs / 3600;
        if hours > 0 {
            secs -= hours * 3600;
            write!(f, "{hours}h")?;
        }

        let minutes = secs / 60;
        if minutes > 0 {
            secs -= minutes * 60;
            write!(f, "{minutes}m")?;
        }

        if secs > 0 {
            write!(f, "{secs}s")?;
        }

        if ms > 0 {
            write!(f, "{ms}ms")?;
        }

        Ok(())
    }
}

impl fmt::Debug for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_valid_duration_succeeds() {
        let test_cases = vec![
            Duration::from_secs(0),
            Duration::from_secs(3600),
            Duration::from_secs(1800),
            Duration::from_secs(10),
            Duration::from_millis(500),
            Duration::from_secs(9000),
            Duration::from_secs(5410),
            Duration::new(7200, 600_000_000),
            Duration::new(7200 + 1800, 600_000_000),
            Duration::new(7200 + 1800 + 10, 600_000_000),
            Duration::from_millis(MAX_DURATION_MS_U64),
        ];

        for (idx, duration) in test_cases.iter().enumerate() {
            assert!(
                duration.is_ok(),
                "{idx:?}: Duration {duration:?} should be OK"
            );
        }
    }

    #[test]
    fn from_invalid_duration_rejects_sub_millisecond_and_overflow() {
        let test_cases = vec![
            (
                Duration::from_micros(100),
                Err("Cannot express sub-millisecond precision in GEP-2257".to_string()),
            ),
            (
                Duration::from_secs(10000 * 86400),
                Err("Duration exceeds GEP-2257 maximum 99999h59m59s999ms".to_string()),
            ),
            (
                Duration::from_millis(MAX_DURATION_MS_U64 + 1),
                Err("Duration exceeds GEP-2257 maximum 99999h59m59s999ms".to_string()),
            ),
        ];

        for (idx, (duration, expected)) in test_cases.into_iter().enumerate() {
            assert_eq!(
                duration, expected,
                "{idx:?}: Duration {duration:?} should be an error"
            );
        }
    }

    #[test]
    fn from_str_parses_gep2257_strings() {
        let test_cases = vec![
            ("0h", Duration::from_secs(0)),
            ("0s", Duration::from_secs(0)),
            ("0h0m0s", Duration::from_secs(0)),
            ("1h", Duration::from_secs(3600)),
            ("30m", Duration::from_secs(1800)),
            ("10s", Duration::from_secs(10)),
            ("500ms", Duration::from_millis(500)),
            ("2h30m", Duration::from_secs(9000)),
            ("150m", Duration::from_secs(9000)),
            ("7230s", Duration::from_secs(7230)),
            ("1h30m10s", Duration::from_secs(5410)),
            ("10s30m1h", Duration::from_secs(5410)),
            ("100ms200ms300ms", Duration::from_millis(600)),
            (
                "99999h59m59s999ms",
                Duration::from_millis(MAX_DURATION_MS_U64),
            ),
            ("1d", Err("Invalid duration format".to_string())),
            ("1", Err("Invalid duration format".to_string())),
            ("1m1", Err("Invalid duration format".to_string())),
            (
                "1h30m10s20ms50h",
                Err("Invalid duration format".to_string()),
            ),
            ("999999h", Err("Invalid duration format".to_string())),
            ("1.5h", Err("Invalid duration format".to_string())),
            ("-15m", Err("Invalid duration format".to_string())),
            ("100ns", Err("Invalid duration format".to_string())),
            (
                "99999h59m59s1000ms",
                Err("Duration exceeds GEP-2257 maximum 99999h59m59s999ms".to_string()),
            ),
        ];

        for (idx, (duration_str, expected)) in test_cases.into_iter().enumerate() {
            assert_eq!(
                Duration::from_str(duration_str),
                expected,
                "{idx:?}: Duration {duration_str:?} should be {expected:?}",
            );
        }
    }

    #[test]
    fn format_follows_gep2257_rules() {
        let test_cases = vec![
            (Duration::from_secs(0), "0s".to_string()),
            (Duration::from_secs(3600), "1h".to_string()),
            (Duration::from_secs(1800), "30m".to_string()),
            (Duration::from_secs(10), "10s".to_string()),
            (Duration::from_millis(500), "500ms".to_string()),
            (Duration::from_secs(9000), "2h30m".to_string()),
            (Duration::from_secs(5410), "1h30m10s".to_string()),
            (Duration::new(7200, 600_000_000), "2h600ms".to_string()),
        ];

        for (idx, (duration, expected)) in test_cases.into_iter().enumerate() {
            assert!(
                duration.as_ref().is_ok_and(|d| format!("{d}") == expected),
                "{idx:?}: Duration {duration:?} should be {expected:?}",
            );
        }
    }

    #[test]
    fn into_std_duration_round_trips() {
        let d = Duration::from_secs(90).expect("valid");
        let std: StdDuration = d.into();
        assert_eq!(std, StdDuration::from_secs(90));
    }
}
