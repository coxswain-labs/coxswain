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
    /// True iff at least one requested entry is a concrete `IPAddress` that
    /// parses as an IP — the exact set the VIP reconciler will try to pin as a
    /// clusterIP (mirrors `operator::render_shared::requested_static_cluster_ips`).
    /// When false (e.g. a Hostname-only request) the reconciler takes the auto
    /// path and can never adjudicate the request, so an `AddressNotUsable` must
    /// settle rather than wait for a `vip_failures` verdict that cannot come.
    pub(crate) requests_pinnable_ip: bool,
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
            requests_pinnable_ip: false,
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
    /// applied when [`Self::should_hold_pending`] says the negative is unconfirmed.
    pub(crate) fn hold_pending_address(&mut self) {
        self.programmed_override = None;
        self.status_addresses.clear();
    }

    /// Whether an `AddressNotUsable` outcome is *unconfirmed* and must be held at
    /// `Pending` rather than settled at the current generation.
    ///
    /// A settled negative is trustworthy only when one of two authorities backs
    /// it: the VIP reconciler recorded a definitive provisioning failure
    /// (`vip_confirmed_failed` — every requested clusterIP permanently rejected),
    /// or the resolved VIP satisfies at least one requested address
    /// (`status_addresses` non-empty — the request was honored as far as a
    /// single-address VIP can; the remaining mismatch is real, e.g. the
    /// conformance `[unusable, usable]` phase). Otherwise the mismatch is
    /// indistinguishable from a VIP mid-provisioning or mid-repin (the operator
    /// deletes + defer-recreates the Service to repin a clusterIP, so the writer
    /// can observe a *resolved-but-stale* address with zero requested matches) —
    /// settling there strands `AddressNotUsable` until an unrelated Gateway
    /// event, because the VIP reconciler fires none (#558).
    ///
    /// The zero-match hold applies only while a `vip_failures` verdict can still
    /// arrive: per-Gateway VIP addressing must be on (`vip_addressing_enabled` —
    /// legacy mode never runs the VIP reconciler) and the request must contain a
    /// pinnable IP ([`Self::requests_pinnable_ip`] — a Hostname-only request is
    /// never adjudicated). A non-adjudicable negative settles immediately; the
    /// caller's slow requeue on settled negatives still self-heals it if a
    /// coincidental match (e.g. an LB-assigned hostname) shows up later.
    #[must_use]
    pub(crate) fn should_hold_pending(
        &self,
        awaiting_own_vip: bool,
        vip_confirmed_failed: bool,
        vip_addressing_enabled: bool,
    ) -> bool {
        let adjudicable = vip_addressing_enabled && self.requests_pinnable_ip;
        self.is_address_not_usable()
            && !vip_confirmed_failed
            && (awaiting_own_vip || (adjudicable && self.status_addresses.is_empty()))
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
                    requests_pinnable_ip: false,
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

    // Mirrors `operator::render_shared::requested_static_cluster_ips`: the
    // entries the VIP reconciler will actually try to pin as a clusterIP.
    let requests_pinnable_ip = classified.iter().any(|r| {
        r.type_ == SupportedAddressType::IpAddress
            && r.value
                .as_deref()
                .is_some_and(|v| v.parse::<std::net::IpAddr>().is_ok())
    });

    StaticAddressOutcome {
        accepted_override: None,
        programmed_override: (!all_usable).then_some(GatewayConditionReason::AddressNotUsable),
        status_addresses,
        feature_engaged: true,
        requests_pinnable_ip,
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
    fn hold_pending_matrix() {
        // The #558 discriminator: an AddressNotUsable is held at Pending unless
        // a definitive vip_failures entry or a partial match settles it — and
        // the zero-match hold requires the VIP reconciler to be able to
        // adjudicate (addressing on + a pinnable IP requested).

        // VIP unresolved (nothing bound), no confirmed failure → hold.
        let awaiting =
            evaluate_static_addresses(&[req(Some("IPAddress"), Some("10.96.0.10"))], &[]);
        assert!(awaiting.should_hold_pending(true, false, true));

        // VIP resolved to a stale/wrong address (mid-repin window): zero
        // requested matches, no confirmed failure → hold, not settle.
        let repin_window = evaluate_static_addresses(
            &[req(Some("IPAddress"), Some("10.96.0.10"))],
            &[ip("10.96.0.99")],
        );
        assert!(repin_window.is_address_not_usable());
        assert!(repin_window.requests_pinnable_ip);
        assert!(repin_window.should_hold_pending(false, false, true));

        // Definitive vip_failures entry → settle even with zero matches.
        assert!(!repin_window.should_hold_pending(false, true, true));
        assert!(!awaiting.should_hold_pending(true, true, true));

        // Legacy mode (per-Gateway VIP addressing off): the VIP reconciler
        // never runs, no verdict can arrive → settle, never hold.
        assert!(!repin_window.should_hold_pending(false, false, false));

        // Hostname-only request: the VIP reconciler pins only IPs, so it never
        // adjudicates this request → settle once the VIP is resolved…
        let hostname_only = evaluate_static_addresses(
            &[req(Some("Hostname"), Some("gw.example.com"))],
            &[ip("10.96.0.99")],
        );
        assert!(hostname_only.is_address_not_usable());
        assert!(!hostname_only.requests_pinnable_ip);
        assert!(!hostname_only.should_hold_pending(false, false, true));
        // …but still hold while the VIP itself is unresolved (an LB hostname
        // may yet arrive and match).
        assert!(hostname_only.should_hold_pending(true, false, true));

        // Partial match ([unusable, usable] with the usable one bound): the VIP
        // reconciler honored the request as far as it can → settle.
        let partial = evaluate_static_addresses(
            &[
                req(Some("IPAddress"), Some("192.0.2.1")),
                req(Some("IPAddress"), Some("10.96.0.10")),
            ],
            &[ip("10.96.0.10")],
        );
        assert!(partial.is_address_not_usable());
        assert!(!partial.should_hold_pending(false, false, true));

        // Fully usable → nothing to hold.
        let usable = evaluate_static_addresses(
            &[req(Some("IPAddress"), Some("10.96.0.10"))],
            &[ip("10.96.0.10")],
        );
        assert!(!usable.should_hold_pending(false, false, true));

        // Deterministic Invalid (unsupported type) is never held.
        let invalid = evaluate_static_addresses(&[req(Some("test/fake"), Some("x"))], &[]);
        assert!(!invalid.should_hold_pending(true, false, true));
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
