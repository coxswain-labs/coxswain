//! Upstream retry policy: the [`RetryOn`] condition bitset and the [`RetryPolicy`]
//! that a [`BackendGroup`](super::backend::BackendGroup) carries — retrying is an
//! upstream-connection concern, read by the proxy in `fail_to_connect` and
//! `upstream_response_filter`.

/// Conditions under which the proxy retries an upstream attempt, as a compact
/// bitset parsed from the `ingress.coxswain-labs.dev/retry-on` annotation.
///
/// Kept `Copy` and allocation-free so a [`RetryPolicy`] adds no heap overhead to
/// the hot [`BackendGroup`](super::backend::BackendGroup).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetryOn(u8);

impl RetryOn {
    /// Retry when the upstream TCP connection cannot be established (`connect-failure`).
    pub const CONNECT_FAILURE: Self = Self(0b001);
    /// Retry when establishing the upstream connection times out (`timeout`).
    pub const TIMEOUT: Self = Self(0b010);
    /// Retry when the upstream returns a 5xx response (`5xx`).
    pub const HTTP_5XX: Self = Self(0b100);

    /// The empty set — no conditions.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// `true` when no retry conditions are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// `true` when every bit in `other` is also set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Add the conditions in `other` to this set (in place).
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

impl std::ops::BitOr for RetryOn {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Per-route upstream retry policy parsed from the Ingress `max-retries` and
/// `retry-on` annotations.
///
/// Carried on [`BackendGroup`](super::backend::BackendGroup) (alongside
/// `protocol`/`tls`) because retrying is an upstream-connection concern; the
/// proxy reads it in `fail_to_connect` and `upstream_response_filter`. A default
/// `RetryPolicy` (`max_retries == 0` or an empty [`RetryOn`]) disables retries entirely.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Maximum number of retries after the initial attempt.
    pub max_retries: u32,
    /// Conditions that trigger a retry.
    pub on: RetryOn,
}

impl RetryPolicy {
    /// Construct a retry policy from a max-retry count and a condition set.
    #[must_use]
    pub fn new(max_retries: u32, on: RetryOn) -> Self {
        Self { max_retries, on }
    }

    /// `true` when this policy will never retry (no budget or no conditions).
    #[must_use]
    pub fn is_disabled(self) -> bool {
        self.max_retries == 0 || self.on.is_empty()
    }
}
