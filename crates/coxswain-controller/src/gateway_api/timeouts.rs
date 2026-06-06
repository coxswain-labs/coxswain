//! Parses GEP-2257 (Go `time.ParseDuration`) duration strings into `std::time::Duration`.

use crate::gw_types::v::httproutes::HttpRouteRulesTimeouts;
use coxswain_core::routing::RouteTimeouts;

/// Parse a Gateway API GEP-2257 duration string (Go `time.ParseDuration` format).
///
/// Supported units: `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`. Values may be compounded
/// without spaces (`"1h30m"`).
///
/// Returns `None` for **both** invalid input and zero values (`"0s"`, `"0"`).
/// Per GEP-2257, zero is treated as "unset" — the same as omitting the field entirely.
pub(super) fn parse_gateway_duration(s: &str) -> Option<std::time::Duration> {
    if s.is_empty() || s == "0" {
        return None;
    }
    let mut total = std::time::Duration::ZERO;
    let mut remaining = s;
    while !remaining.is_empty() {
        // Consume the numeric part (digits + optional single decimal point).
        let num_end = remaining
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(remaining.len());
        if num_end == 0 {
            tracing::warn!(raw = s, "Skipping invalid Gateway API duration string");
            return None;
        }
        let num: f64 = match remaining[..num_end].parse() {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(raw = s, "Skipping invalid Gateway API duration string");
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
            "ns" => std::time::Duration::from_nanos(num as u64),
            "us" | "µs" => std::time::Duration::from_micros(num as u64),
            "ms" => std::time::Duration::from_millis(num as u64),
            "s" => std::time::Duration::from_secs_f64(num),
            "m" => std::time::Duration::from_secs_f64(num * 60.0),
            "h" => std::time::Duration::from_secs_f64(num * 3600.0),
            _ => {
                tracing::warn!(
                    raw = s,
                    unit,
                    "Skipping unsupported unit in Gateway API duration string"
                );
                return None;
            }
        };
        total += unit_dur;
    }
    if total.is_zero() { None } else { Some(total) }
}

pub(super) fn parse_rule_timeouts(t: &HttpRouteRulesTimeouts) -> RouteTimeouts {
    RouteTimeouts {
        request: t.request.as_deref().and_then(parse_gateway_duration),
        backend_request: t
            .backend_request
            .as_deref()
            .and_then(parse_gateway_duration),
    }
}
