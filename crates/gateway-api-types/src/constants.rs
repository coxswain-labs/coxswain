//! Gateway API condition `type`/`reason` constants, parsed directly from the upstream Go
//! source (`apis/v1`, `apisx/v1alpha1`) at the tag pinned in `.gateway-api-version` — see
//! the repo-root `xtask` crate. Regenerate with
//! `cargo run -p xtask -- gateway-api-types` — do not edit by hand.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayClassConditionReason {
    Accepted,
    InvalidParameters,
    Pending,
    Unsupported,
    Waiting,
    SupportedVersion,
    UnsupportedVersion,
}

impl std::fmt::Display for GatewayClassConditionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayClassConditionType {
    Accepted,
    SupportedVersion,
}

impl std::fmt::Display for GatewayClassConditionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayConditionReason {
    Programmed,
    Invalid,
    NoResources,
    AddressNotAssigned,
    AddressNotUsable,
    ConfigurationChanged,
    Accepted,
    ListenersNotValid,
    Pending,
    UnsupportedAddress,
    InvalidParameters,
    Scheduled,
    NotReconciled,
    ResolvedRefs,
    InvalidClientCertificateRef,
    RefNotPermitted,
    ListenersNotResolved,
    Ready,
    ListenersNotReady,
}

impl std::fmt::Display for GatewayConditionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayConditionType {
    Programmed,
    InsecureFrontendValidationMode,
    Accepted,
    Scheduled,
    ResolvedRefs,
    Ready,
}

impl std::fmt::Display for GatewayConditionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerConditionReason {
    HostnameConflict,
    ProtocolConflict,
    NoConflicts,
    Accepted,
    Attached,
    PortUnavailable,
    UnsupportedProtocol,
    NoValidCACertificate,
    UnsupportedValue,
    ResolvedRefs,
    InvalidCertificateRef,
    InvalidRouteKinds,
    RefNotPermitted,
    InvalidCACertificateRef,
    InvalidCACertificateKind,
    Programmed,
    Invalid,
    Pending,
    OverlappingHostnames,
    OverlappingCertificates,
    Ready,
}

impl std::fmt::Display for ListenerConditionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerConditionType {
    Conflicted,
    Accepted,
    Detached,
    ResolvedRefs,
    Programmed,
    OverlappingTLSConfig,
    Ready,
}

impl std::fmt::Display for ListenerConditionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerEntryConditionReason {
    HostnameConflict,
    ProtocolConflict,
    ListenerConflict,
    Accepted,
    UnsupportedProtocol,
    TooManyListeners,
    ResolvedRefs,
    InvalidCertificateRef,
    InvalidRouteKinds,
    RefNotPermitted,
    Programmed,
    PortUnavailable,
    Pending,
    Invalid,
    Ready,
}

impl std::fmt::Display for ListenerEntryConditionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerEntryConditionType {
    Conflicted,
    Accepted,
    ResolvedRefs,
    Programmed,
    Ready,
}

impl std::fmt::Display for ListenerEntryConditionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerSetConditionReason {
    Programmed,
    Accepted,
    NotAllowed,
    ParentNotAccepted,
    ListenersNotValid,
    Invalid,
    Pending,
}

impl std::fmt::Display for ListenerSetConditionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerSetConditionType {
    Programmed,
    Accepted,
}

impl std::fmt::Display for ListenerSetConditionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshConditionReason {
    Accepted,
    InvalidParameters,
    Pending,
}

impl std::fmt::Display for MeshConditionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshConditionType {
    Accepted,
}

impl std::fmt::Display for MeshConditionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyConditionReason {
    NoValidCACertificate,
    ResolvedRefs,
    InvalidCACertificateRef,
    InvalidKind,
    Accepted,
    Conflicted,
    Invalid,
    TargetNotFound,
}

impl std::fmt::Display for PolicyConditionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyConditionType {
    ResolvedRefs,
    Accepted,
}

impl std::fmt::Display for PolicyConditionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteConditionReason {
    Accepted,
    NotAllowedByListeners,
    NoMatchingListenerHostname,
    NoMatchingParent,
    UnsupportedValue,
    Pending,
    IncompatibleFilters,
    ResolvedRefs,
    RefNotPermitted,
    InvalidKind,
    BackendNotFound,
    UnsupportedProtocol,
}

impl std::fmt::Display for RouteConditionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteConditionType {
    Accepted,
    ResolvedRefs,
    PartiallyInvalid,
}

impl std::fmt::Display for RouteConditionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
