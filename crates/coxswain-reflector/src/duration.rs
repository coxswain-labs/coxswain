//! Shared duration string parser for the `ingress.coxswain-labs.dev/*` annotation
//! namespace and the Gateway API GEP-2257 timeout fields.
//!
//! The format follows Go's `time.ParseDuration`: one or more `<number><unit>` pairs
//! without spaces, e.g. `"5s"`, `"1m30s"`, `"100ms"`. Supported units: `ns`, `us`
//! (or `µs`), `ms`, `s`, `m`, `h`. Zero values (`"0"`, `"0s"`) are treated as "not
//! set" and return `None`, consistent with GEP-2257.

use std::time::Duration;

/// Parse a Go `time.ParseDuration`-style string into a [`Duration`].
///
/// Returns `None` for empty, zero-valued, or syntactically invalid input.
/// Emits a `WARN` tracing event on malformed input so operators can spot
/// misconfigured annotations or HTTPRoute timeout fields.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use coxswain_reflector::duration::parse_duration;
///
/// assert_eq!(parse_duration("5s"),  Some(Duration::from_secs(5)));
/// assert_eq!(parse_duration("1m"),  Some(Duration::from_secs(60)));
/// assert_eq!(parse_duration("0s"),  None);
/// assert_eq!(parse_duration("bad"), None);
/// ```
#[must_use]
pub fn parse_duration(s: &str) -> Option<Duration> {
    if s.is_empty() || s == "0" {
        return None;
    }
    let mut total = Duration::ZERO;
    let mut remaining = s;
    while !remaining.is_empty() {
        // Consume the numeric part (digits + optional single decimal point).
        let num_end = remaining
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(remaining.len());
        if num_end == 0 {
            tracing::warn!(raw = s, "invalid duration string");
            return None;
        }
        let num: f64 = match remaining[..num_end].parse() {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(raw = s, "invalid duration string");
                return None;
            }
        };
        remaining = &remaining[num_end..];
        // Consume the unit part.
        let unit_end = remaining
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(remaining.len());
        let unit = &remaining[..unit_end];
        remaining = &remaining[unit_end..];
        let unit_dur = match unit {
            "ns" => Duration::from_nanos(num as u64),
            "us" | "µs" => Duration::from_micros(num as u64),
            "ms" => Duration::from_millis(num as u64),
            "s" => Duration::from_secs_f64(num),
            "m" => Duration::from_secs_f64(num * 60.0),
            "h" => Duration::from_secs_f64(num * 3600.0),
            _ => {
                tracing::warn!(raw = s, unit, "unsupported unit in duration string");
                return None;
            }
        };
        total += unit_dur;
    }
    if total.is_zero() { None } else { Some(total) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_values() {
        assert_eq!(parse_duration("10s"), Some(Duration::from_secs(10)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("1m"), Some(Duration::from_secs(60)));
        assert_eq!(
            parse_duration("2h45m"),
            Some(Duration::from_secs(2 * 3600 + 45 * 60))
        );
        assert_eq!(parse_duration("100ns"), Some(Duration::from_nanos(100)));
        assert_eq!(parse_duration("100us"), Some(Duration::from_micros(100)));
    }

    #[test]
    fn zero_returns_none() {
        assert_eq!(parse_duration("0s"), None);
        assert_eq!(parse_duration("0"), None);
        assert_eq!(parse_duration(""), None);
    }

    #[test]
    #[tracing_test::traced_test]
    fn invalid_returns_none_and_warns() {
        assert_eq!(parse_duration("10x"), None);
        assert_eq!(parse_duration("abc"), None);
        assert!(logs_contain("invalid duration string") || logs_contain("unsupported unit"));
    }
}
