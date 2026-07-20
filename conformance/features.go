package conformance_test

import (
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

// Plural resource names of the Gateway API kinds this suite gates on.
const (
	pluralGRPCRoutes   = "grpcroutes"
	pluralTLSRoutes    = "tlsroutes"
	pluralTCPRoutes    = "tcproutes"
	pluralUDPRoutes    = "udproutes"
	pluralListenerSets = "listenersets"
)

// conformanceProfile pairs a profile with the CRD that must exist to claim it.
//
// The name is a plain string rather than a `suite.Gateway*ConformanceProfileName`
// constant: the TCP and UDP constants do not exist in the Gateway API v1.4 Go
// module, so referencing them would break compilation against the suite version
// that matches a v1.4 cluster. `ConformanceProfileName` is a string alias, so
// this is the same value by a route that always compiles.
type conformanceProfile struct {
	name string
	// requiresKind is the plural CRD name backing the profile; empty means the
	// profile is always claimable.
	requiresKind string
}

var conformanceProfiles = []conformanceProfile{
	{name: "GATEWAY-HTTP"},
	{name: "GATEWAY-GRPC", requiresKind: pluralGRPCRoutes},
	{name: "GATEWAY-TLS", requiresKind: pluralTLSRoutes},
	{name: "GATEWAY-TCP", requiresKind: pluralTCPRoutes},
	{name: "GATEWAY-UDP", requiresKind: pluralUDPRoutes},
}

// profilesFor returns the profiles the installed CRDs can actually support.
//
// Claiming a profile makes the suite run every test in it, and those tests
// create the profile's route kind — so claiming GATEWAY-TCP on a cluster with
// no TCPRoute CRD fails a suite that is otherwise behaving correctly.
func profilesFor(caps clusterCapabilities) []suite.ConformanceProfileName {
	var claimed []suite.ConformanceProfileName
	for _, profile := range conformanceProfiles {
		if profile.requiresKind != "" && !caps.hasKind(profile.requiresKind) {
			continue
		}
		claimed = append(claimed, suite.ConformanceProfileName(profile.name))
	}
	return claimed
}

// gatedFeature pairs a declared feature with what the cluster must install for
// the declaration to be true.
//
// At most one of `requiresKind` / `requiresField` is set; both empty means the
// feature rides on `Gateway`/`HTTPRoute`, which exist at every supported
// version. This mirrors the Rust `SUPPORTED_FEATURES` table entry for entry —
// `scripts/check-supported-features.sh` enforces that the two agree.
//
// `name` is a plain string, not a `features.SupportXxx` constant. The constants
// are added as features land, so 11 of the ones below — `SupportTCPRoute`,
// `SupportListenerSet`, the three redirect-status-code features, the GEP-91
// pair, and others — simply do not exist in the Gateway API v1.4 Go module,
// and naming them makes this file fail to COMPILE against the suite version
// matching a v1.4 cluster. `FeatureName` is a string alias and each constant's
// value is exactly the feature name, so the string form is the same value by a
// route that compiles against every supported module version.
type gatedFeature struct {
	name          string
	requiresKind  string
	requiresField string
}

var gatedFeatures = []gatedFeature{
	// Core (required for HTTP profile conformance claim)
	{name: "Gateway"},   // #34
	{name: "HTTPRoute"}, // #34
	// Extended: matching (#7)
	{name: "HTTPRouteQueryParamMatching"},
	{name: "HTTPRouteMethodMatching"},
	// Extended: header modification (#13, #167)
	{name: "HTTPRouteBackendRequestHeaderModification"},
	{name: "HTTPRouteResponseHeaderModification"},
	// Extended: redirect and rewrite (#13)
	{name: "HTTPRoutePortRedirect"},
	{name: "HTTPRouteSchemeRedirect"},
	{name: "HTTPRoutePathRedirect"},
	{name: "HTTPRouteHostRewrite"},
	{name: "HTTPRoutePathRewrite"},
	// Extended: timeouts (#14)
	{name: "HTTPRouteRequestTimeout"},
	{name: "HTTPRouteBackendTimeout"},
	// Extended: redirect status codes (#34)
	{name: "HTTPRoute303RedirectStatusCode"},
	{name: "HTTPRoute307RedirectStatusCode"},
	{name: "HTTPRoute308RedirectStatusCode"},
	// Extended: named route rules (#34)
	{name: "HTTPRouteNamedRouteRule"},
	// Extended: HTTP listener isolation (#34)
	{name: "GatewayHTTPListenerIsolation"},
	// Extended: CORS filter — GEP-1767 (#41). The `cors` filter is absent from
	// the HTTPRoute schema below Gateway API v1.5.
	{name: "HTTPRouteCORS", requiresField: "HTTPRouteCORS"},
	// Extended: RequestMirror filter — GEP-3171 (#261)
	{name: "HTTPRouteRequestMirror"},
	{name: "HTTPRouteRequestMultipleMirrors"},
	{name: "HTTPRouteRequestPercentageMirror"},
	// Extended: HTTPS misdirected-request detection — GEP-3567 (#96)
	{name: "GatewayHTTPSListenerDetectMisdirectedRequests"},
	// Extended: port 8080 listener (#34)
	{name: "GatewayPort8080"},
	// Extended: empty Gateway address value (#34)
	{name: "GatewayAddressEmpty"},
	// Extended: static Gateway addresses — GatewayStaticAddresses (#260).
	// Coxswain honors a requested IPAddress by pinning it as the per-Gateway
	// VIP Service clusterIP (deterministic accept/reject vs the apiserver
	// service-CIDR). Requires UsableNetworkAddresses/UnusableNetworkAddresses,
	// injected by scripts/setup-conformance.sh.
	{name: "GatewayStaticAddresses"},
	// Standard: backend client-certificate (mTLS to upstream) — GEP-3155 (#87)
	{name: "GatewayBackendClientCertificate"},
	// Standard: frontend client-certificate validation — GEP-91 (#86). The
	// `spec.tls.frontend` subtree is absent from the Gateway schema below
	// Gateway API v1.5.
	{name: "GatewayFrontendClientCertificateValidation", requiresField: "GatewayFrontendTLS"},
	{name: "GatewayFrontendClientCertificateValidationInsecureFallback", requiresField: "GatewayFrontendTLS"},
	// Extended: parentRef port mismatch → NoMatchingParent (#34)
	{name: "HTTPRouteDestinationPortMatching"},
	// Extended: per-port listener routing (#82, #98)
	{name: "HTTPRouteParentRefPort"},
	// Extended: backend protocol selection — GEP-1911 (#90, #32)
	{name: "HTTPRouteBackendProtocolH2C"},
	{name: "HTTPRouteBackendProtocolWebSocket"},
	// Core: BackendTLSPolicy — GEP-1897 (#16)
	// Extended: BackendTLSPolicy subjectAltNames — GEP-1897 (#133)
	{name: "BackendTLSPolicy", requiresKind: "backendtlspolicies"},
	{name: "BackendTLSPolicySANValidation", requiresKind: "backendtlspolicies"},
	// Standard: ReferenceGrant — GEP-709 (#3, declaration: #166)
	{name: "ReferenceGrant", requiresKind: "referencegrants"},
	// Standard: GRPCRoute — GEP-1016 (#33)
	{name: "GRPCRoute", requiresKind: pluralGRPCRoutes},
	// Extended: named route rules — GEP-995 (#504)
	{name: "GRPCRouteNamedRouteRule", requiresKind: pluralGRPCRoutes},
	// Standard: TLSRoute passthrough — GEP-2643 (#70)
	{name: "TLSRoute", requiresKind: pluralTLSRoutes},
	// Extended: TLSRoute terminate mode — #481
	{name: "TLSRouteModeTerminate", requiresKind: pluralTLSRoutes},
	// Extended: TLSRoute mixed (passthrough+terminate on same port) — #481
	{name: "TLSRouteModeMixed", requiresKind: pluralTLSRoutes},
	// Standard: TCPRoute — GEP-1901 (#505)
	{name: "TCPRoute", requiresKind: pluralTCPRoutes},
	// Standard: UDPRoute — GEP-2645 (#506)
	{name: "UDPRoute", requiresKind: pluralUDPRoutes},
	// Standard: ListenerSet — GEP-1713 (#93)
	{name: "ListenerSet", requiresKind: pluralListenerSets},
	// Extended: Gateway infrastructure metadata propagation — GEP-1867 (#482).
	// spec.infrastructure.{labels,annotations} propagate onto provisioned
	// resources; in shared mode the carrier is a per-Gateway identity
	// ServiceAccount in the Gateway's namespace.
	{name: "GatewayInfrastructurePropagation"},
}

// supportedFeatures returns the features this cluster's CRDs can express.
func supportedFeatures(caps clusterCapabilities) []features.FeatureName {
	var declared []features.FeatureName
	for _, feature := range gatedFeatures {
		if feature.requiresKind != "" && !caps.hasKind(feature.requiresKind) {
			continue
		}
		if feature.requiresField != "" && !caps.hasField(feature.requiresField) {
			continue
		}
		declared = append(declared, features.FeatureName(feature.name))
	}
	return declared
}
