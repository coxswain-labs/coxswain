//! `GatewayStaticAddresses` (`Gateway.spec.addresses`) validation, shared by the
//! shared-pool status writer ([`crate::controller::gateway_status`]) and the
//! dedicated-mode status writer ([`crate::operator::status`]).
//!
//! Pure and infallible: given the requested `spec.addresses` and the addresses
//! coxswain actually bound to the backing Service (`resolved`), it computes the
//! `Accepted`/`Programmed` condition overrides and the gated `status.addresses`
//! list. No I/O, no allocation beyond the output set.
//!
//! ## Why "match the bound address" is the usability test
//!
//! Coxswain honors a requested address by setting it on the per-Gateway VIP
//! Service's immutable `spec.clusterIP` (see
//! `crate::operator::reconciler::reconcile_all_vips`). The apiserver assigns an
//! in-CIDR free IP exactly and rejects an out-of-range one, so a requested
//! address is *usable* iff it shows up in the resolved Service address. Anything
//! requested but not bound is `AddressNotUsable`; an unsupported `type` is
//! `UnsupportedAddress` (rejected before provisioning).

use coxswain_reflector::gw_types::constants::GatewayConditionReason;
use coxswain_reflector::gw_types::v::gateways::GatewayAddresses;

/// An address `type` coxswain can place in `status.addresses`. Per the Gateway
/// API spec an absent `spec.addresses[*].type` defaults to `IPAddress`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SupportedAddressType {
    /// A bare IPv4/IPv6 address.
    IpAddress,
    /// A DNS hostname.
    Hostname,
}

impl SupportedAddressType {
    /// The canonical Gateway API string form written to `status.addresses[*].type`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::IpAddress => "IPAddress",
            Self::Hostname => "Hostname",
        }
    }
}

/// A type-tagged address in canonical Gateway-API string form. Used both for the
/// addresses coxswain actually bound (`resolved` input) and for the gated
/// `status.addresses` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TypedAddress {
    /// The address type (`IPAddress`/`Hostname`).
    pub(crate) type_: SupportedAddressType,
    /// The address value.
    pub(crate) value: String,
}

impl TypedAddress {
    /// Construct a typed address.
    pub(crate) fn new(type_: SupportedAddressType, value: impl Into<String>) -> Self {
        Self {
            type_,
            value: value.into(),
        }
    }
}

/// Outcome of validating `spec.addresses` against the bound addresses.
///
/// The two `*_override` fields are `None` on the legacy / happy path (the caller
/// keeps emitting `Accepted=True`/`Programmed=True`); `Some(reason)` forces the
/// corresponding condition to `False` with that reason.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaticAddressOutcome {
    /// `Some(GatewayConditionReason::UnsupportedAddress)` forces
    /// `Accepted=(False, reason)`.
    pub(crate) accepted_override: Option<GatewayConditionReason>,
    /// `Some(reason)` forces `Programmed=(False, reason)` —
    /// `AddressNotUsable`, or `Invalid` when `accepted_override` is also set.
    pub(crate) programmed_override: Option<GatewayConditionReason>,
    /// The addresses to publish in `status.addresses`. Only the *usable* bound
    /// addresses — never the unusable or invalid requested values.
    pub(crate) status_addresses: Vec<TypedAddress>,
    /// True iff the Gateway requested at least one concrete (non-empty-value)
    /// static address. When false the caller keeps its legacy auto-address
    /// behaviour (`GatewayAddressEmpty`) untouched.
    pub(crate) feature_engaged: bool,
}

impl StaticAddressOutcome {
    /// The not-engaged outcome: no overrides, no gated addresses, caller keeps
    /// its legacy auto-address behaviour. Used when `spec.addresses` is absent or
    /// requests only empty (auto-assign) values.
    pub(crate) fn not_engaged() -> Self {
        Self {
            accepted_override: None,
            programmed_override: None,
            status_addresses: Vec::new(),
            feature_engaged: false,
        }
    }

    /// Whether the `Programmed` override is the provisioning-sensitive
    /// `AddressNotUsable` — an empty/mismatched `resolved` set — as opposed to a
    /// deterministic `Invalid` (unsupported address *type*). Only the former is
    /// ambiguous between "VIP still provisioning" and "settled unusable": both
    /// present identically (no bound address) until the VIP reconciler either
    /// binds the requested clusterIP or confirms it cannot (#533 provisioning gap).
    #[must_use]
    pub(crate) fn is_address_not_usable(&self) -> bool {
        self.programmed_override == Some(GatewayConditionReason::AddressNotUsable)
    }

    /// Downgrade a premature `AddressNotUsable` to "still provisioning": clear the
    /// `Programmed` override and any gated addresses so the shared status writer's
    /// convergence gate holds `Programmed` at `gen-1` (`Pending`) instead of
    /// stamping a settled negative while the VIP is still being provisioned. Only
    /// applied while the VIP is unresolved AND the operator has not recorded a
    /// definitive provisioning failure for the Gateway.
    pub(crate) fn hold_pending_address(&mut self) {
        self.programmed_override = None;
        self.status_addresses.clear();
    }
}

/// One classified `spec.addresses` entry: a supported type plus either a
/// concrete value or `None` (empty value → auto-assign, `GatewayAddressEmpty`).
struct RequestedAddress {
    type_: SupportedAddressType,
    /// `None` when the requested value is empty (auto-assign).
    value: Option<String>,
}

/// Classify one `spec.addresses` entry. `Err(())` when the `type` is not one
/// coxswain supports. An absent `type` defaults to `IPAddress` per the spec; an
/// empty (or absent) `value` is the auto-assign wildcard.
fn classify(addr: &GatewayAddresses) -> Result<RequestedAddress, ()> {
    let type_ = match addr.r#type.as_deref() {
        None | Some("IPAddress") => SupportedAddressType::IpAddress,
        Some("Hostname") => SupportedAddressType::Hostname,
        Some(_) => return Err(()),
    };
    let value = addr
        .value
        .as_deref()
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    Ok(RequestedAddress { type_, value })
}

/// Validate requested `spec.addresses` against the addresses coxswain actually
/// bound (`resolved`), producing the condition overrides and the gated
/// `status.addresses` list.
///
/// Rules:
/// 1. Any entry whose `type` is unsupported → `accepted_override =
///    UnsupportedAddress`, `programmed_override = Invalid`, no published
///    addresses. (Rejected before provisioning.)
/// 2. The feature is *engaged* iff at least one entry has a non-empty value. A
///    request consisting only of empty values stays on the legacy auto path
///    (`GatewayAddressEmpty`) — returns the not-engaged outcome.
/// 3. When engaged and all types are supported: a requested entry is *usable*
///    iff it appears in `resolved` (a concrete entry matches by type+value; an
///    empty-value entry matches any resolved address of that type).
///    `status_addresses` = the bound addresses that satisfied a request. If any
///    requested entry is unusable (or `resolved` is empty) →
///    `programmed_override = AddressNotUsable`.
///
/// The "every requested address must appear in `resolved`" rule is what makes
/// the conformance ladder pass regardless of pool ordering: a request of
/// `[unusable, usable]` can have at most one bound clusterIP, so not all entries
/// match → `AddressNotUsable`; a request of `[usable]` with that IP bound →
/// fully satisfied → `Programmed`.
#[must_use]
pub(crate) fn evaluate_static_addresses(
    requested: &[GatewayAddresses],
    resolved: &[TypedAddress],
) -> StaticAddressOutcome {
    if requested.is_empty() {
        return StaticAddressOutcome::not_engaged();
    }

    let mut classified = Vec::with_capacity(requested.len());
    for addr in requested {
        match classify(addr) {
            Ok(req) => classified.push(req),
            Err(()) => {
                // An unsupported type rejects the whole Gateway before any
                // provisioning. status.addresses is cleared (empty) and the
                // feature is treated as engaged so the writer publishes `[]`.
                return StaticAddressOutcome {
                    accepted_override: Some(GatewayConditionReason::UnsupportedAddress),
                    programmed_override: Some(GatewayConditionReason::Invalid),
                    status_addresses: Vec::new(),
                    feature_engaged: true,
                };
            }
        }
    }

    // Not engaged unless at least one concrete value was requested. A pure
    // empty-value request is the existing GatewayAddressEmpty auto path.
    if !classified.iter().any(|r| r.value.is_some()) {
        return StaticAddressOutcome::not_engaged();
    }

    // Each requested entry must be satisfied by a bound address.
    let satisfied = |req: &RequestedAddress| match &req.value {
        Some(value) => resolved
            .iter()
            .any(|r| r.type_ == req.type_ && &r.value == value),
        None => resolved.iter().any(|r| r.type_ == req.type_),
    };
    let all_usable = classified.iter().all(satisfied);

    // Publish the bound addresses that satisfied a request (never the unusable
    // requested values). `resolved` is already unique and stably ordered.
    let status_addresses: Vec<TypedAddress> = resolved
        .iter()
        .filter(|r| {
            classified.iter().any(|req| match &req.value {
                Some(value) => req.type_ == r.type_ && value == &r.value,
                None => req.type_ == r.type_,
            })
        })
        .cloned()
        .collect();

    StaticAddressOutcome {
        accepted_override: None,
        programmed_override: (!all_usable).then_some(GatewayConditionReason::AddressNotUsable),
        status_addresses,
        feature_engaged: true,
    }
}

#[cfg(test)]
mod tests {
    use super::{SupportedAddressType, TypedAddress, evaluate_static_addresses};
    use coxswain_reflector::gw_types::constants::GatewayConditionReason;
    use coxswain_reflector::gw_types::v::gateways::GatewayAddresses;

    fn req(type_: Option<&str>, value: Option<&str>) -> GatewayAddresses {
        GatewayAddresses {
            r#type: type_.map(str::to_string),
            value: value.map(str::to_string),
        }
    }

    fn ip(value: &str) -> TypedAddress {
        TypedAddress::new(SupportedAddressType::IpAddress, value)
    }

    #[test]
    fn empty_request_is_not_engaged() {
        let out = evaluate_static_addresses(&[], &[ip("10.0.0.1")]);
        assert!(!out.feature_engaged);
        assert!(out.accepted_override.is_none());
        assert!(out.programmed_override.is_none());
    }

    #[test]
    fn empty_value_only_stays_on_legacy_auto_path() {
        // Pure GatewayAddressEmpty: a request with no concrete value.
        let out = evaluate_static_addresses(&[req(Some("IPAddress"), None)], &[ip("10.0.0.1")]);
        assert!(!out.feature_engaged, "empty-value request must not engage");
    }

    #[test]
    fn unsupported_type_yields_unsupported_address() {
        let out = evaluate_static_addresses(
            &[req(Some("test/fake-invalid-type"), Some("nonsense"))],
            &[],
        );
        assert_eq!(
            out.accepted_override,
            Some(GatewayConditionReason::UnsupportedAddress)
        );
        assert_eq!(
            out.programmed_override,
            Some(GatewayConditionReason::Invalid)
        );
        assert!(out.status_addresses.is_empty());
        assert!(out.feature_engaged);
    }

    #[test]
    fn unsupported_type_among_valid_ones_still_rejects() {
        let out = evaluate_static_addresses(
            &[
                req(Some("test/fake"), Some("x")),
                req(Some("IPAddress"), Some("10.96.0.10")),
            ],
            &[ip("10.96.0.10")],
        );
        assert_eq!(
            out.accepted_override,
            Some(GatewayConditionReason::UnsupportedAddress)
        );
        assert!(out.status_addresses.is_empty());
    }

    #[test]
    fn address_not_usable_detected_and_downgradable() {
        // Requested IP, nothing resolved yet → AddressNotUsable: the ambiguous
        // "provisioning or settled?" case (#533).
        let mut out = evaluate_static_addresses(&[req(Some("IPAddress"), Some("10.96.0.10"))], &[]);
        assert!(out.is_address_not_usable());
        assert_eq!(
            out.programmed_override,
            Some(GatewayConditionReason::AddressNotUsable)
        );
        out.hold_pending_address();
        assert!(!out.is_address_not_usable());
        assert!(out.programmed_override.is_none());
        assert!(out.status_addresses.is_empty());
    }

    #[test]
    fn invalid_type_is_not_address_not_usable() {
        // Unsupported address *type* is a deterministic Invalid — never downgraded.
        let out = evaluate_static_addresses(&[req(Some("test/fake"), Some("x"))], &[]);
        assert!(!out.is_address_not_usable());
    }

    #[test]
    fn usable_address_is_not_address_not_usable() {
        let out = evaluate_static_addresses(
            &[req(Some("IPAddress"), Some("10.96.0.10"))],
            &[ip("10.96.0.10")],
        );
        assert!(!out.is_address_not_usable());
    }

    #[test]
    fn single_usable_address_is_programmed_and_published() {
        let out = evaluate_static_addresses(
            &[req(Some("IPAddress"), Some("10.96.0.10"))],
            &[ip("10.96.0.10")],
        );
        assert!(out.feature_engaged);
        assert!(out.accepted_override.is_none());
        assert!(out.programmed_override.is_none());
        assert_eq!(out.status_addresses, vec![ip("10.96.0.10")]);
    }

    #[test]
    fn default_type_is_ip_address() {
        // Absent type defaults to IPAddress per the spec.
        let out = evaluate_static_addresses(&[req(None, Some("10.96.0.10"))], &[ip("10.96.0.10")]);
        assert!(out.programmed_override.is_none());
        assert_eq!(out.status_addresses, vec![ip("10.96.0.10")]);
    }

    #[test]
    fn usable_and_unusable_together_is_address_not_usable() {
        // Conformance step 2: both requested, only the usable one is bound.
        let out = evaluate_static_addresses(
            &[
                req(Some("IPAddress"), Some("192.0.2.1")),
                req(Some("IPAddress"), Some("10.96.0.10")),
            ],
            &[ip("10.96.0.10")],
        );
        assert!(
            out.accepted_override.is_none(),
            "supported types stay Accepted"
        );
        assert_eq!(
            out.programmed_override,
            Some(GatewayConditionReason::AddressNotUsable)
        );
        // Only the usable bound address is published; the unusable value never is.
        assert_eq!(out.status_addresses, vec![ip("10.96.0.10")]);
    }

    #[test]
    fn usable_requested_but_nothing_bound_is_address_not_usable() {
        // VIP pending or apiserver rejected the requested clusterIP → resolved empty.
        let out = evaluate_static_addresses(&[req(Some("IPAddress"), Some("192.0.2.1"))], &[]);
        assert!(out.accepted_override.is_none());
        assert_eq!(
            out.programmed_override,
            Some(GatewayConditionReason::AddressNotUsable)
        );
        assert!(out.status_addresses.is_empty());
    }

    #[test]
    fn hostname_request_matches_bound_hostname() {
        let resolved = [TypedAddress::new(
            SupportedAddressType::Hostname,
            "gw.example.com",
        )];
        let out =
            evaluate_static_addresses(&[req(Some("Hostname"), Some("gw.example.com"))], &resolved);
        assert!(out.programmed_override.is_none());
        assert_eq!(out.status_addresses, resolved.to_vec());
    }
}
