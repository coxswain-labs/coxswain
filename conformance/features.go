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
type gatedFeature struct {
	name          features.FeatureName
	requiresKind  string
	requiresField string
}

var gatedFeatures = []gatedFeature{
	// Core (required for HTTP profile conformance claim)
	{name: features.SupportGateway},   // #34
	{name: features.SupportHTTPRoute}, // #34
	// Extended: matching (#7)
	{name: features.SupportHTTPRouteQueryParamMatching},
	{name: features.SupportHTTPRouteMethodMatching},
	// Extended: header modification (#13, #167)
	{name: features.SupportHTTPRouteBackendRequestHeaderModification},
	{name: features.SupportHTTPRouteResponseHeaderModification},
	// Extended: redirect and rewrite (#13)
	{name: features.SupportHTTPRoutePortRedirect},
	{name: features.SupportHTTPRouteSchemeRedirect},
	{name: features.SupportHTTPRoutePathRedirect},
	{name: features.SupportHTTPRouteHostRewrite},
	{name: features.SupportHTTPRoutePathRewrite},
	// Extended: timeouts (#14)
	{name: features.SupportHTTPRouteRequestTimeout},
	{name: features.SupportHTTPRouteBackendTimeout},
	// Extended: redirect status codes (#34)
	{name: features.SupportHTTPRoute303RedirectStatusCode},
	{name: features.SupportHTTPRoute307RedirectStatusCode},
	{name: features.SupportHTTPRoute308RedirectStatusCode},
	// Extended: named route rules (#34)
	{name: features.SupportHTTPRouteNamedRouteRule},
	// Extended: HTTP listener isolation (#34)
	{name: features.SupportGatewayHTTPListenerIsolation},
	// Extended: CORS filter — GEP-1767 (#41). The `cors` filter is absent from
	// the HTTPRoute schema below Gateway API v1.5.
	{name: features.SupportHTTPRouteCORS, requiresField: "HTTPRouteCORS"},
	// Extended: RequestMirror filter — GEP-3171 (#261)
	{name: features.SupportHTTPRouteRequestMirror},
	{name: features.SupportHTTPRouteRequestMultipleMirrors},
	{name: features.SupportHTTPRouteRequestPercentageMirror},
	// Extended: HTTPS misdirected-request detection — GEP-3567 (#96)
	{name: features.SupportGatewayHTTPSListenerDetectMisdirectedRequests},
	// Extended: port 8080 listener (#34)
	{name: features.SupportGatewayPort8080},
	// Extended: empty Gateway address value (#34)
	{name: features.SupportGatewayAddressEmpty},
	// Extended: static Gateway addresses — GatewayStaticAddresses (#260).
	// Coxswain honors a requested IPAddress by pinning it as the per-Gateway
	// VIP Service clusterIP (deterministic accept/reject vs the apiserver
	// service-CIDR). Requires UsableNetworkAddresses/UnusableNetworkAddresses,
	// injected by scripts/setup-conformance.sh.
	{name: features.SupportGatewayStaticAddresses},
	// Standard: backend client-certificate (mTLS to upstream) — GEP-3155 (#87)
	{name: features.SupportGatewayBackendClientCertificate},
	// Standard: frontend client-certificate validation — GEP-91 (#86). The
	// `spec.tls.frontend` subtree is absent from the Gateway schema below
	// Gateway API v1.5.
	{name: features.SupportGatewayFrontendClientCertificateValidation, requiresField: "GatewayFrontendTLS"},
	{name: features.SupportGatewayFrontendClientCertificateValidationInsecureFallback, requiresField: "GatewayFrontendTLS"},
	// Extended: parentRef port mismatch → NoMatchingParent (#34)
	{name: features.SupportHTTPRouteDestinationPortMatching},
	// Extended: per-port listener routing (#82, #98)
	{name: features.SupportHTTPRouteParentRefPort},
	// Extended: backend protocol selection — GEP-1911 (#90, #32)
	{name: features.SupportHTTPRouteBackendProtocolH2C},
	{name: features.SupportHTTPRouteBackendProtocolWebSocket},
	// Core: BackendTLSPolicy — GEP-1897 (#16)
	// Extended: BackendTLSPolicy subjectAltNames — GEP-1897 (#133)
	{name: features.SupportBackendTLSPolicy, requiresKind: "backendtlspolicies"},
	{name: features.SupportBackendTLSPolicySANValidation, requiresKind: "backendtlspolicies"},
	// Standard: ReferenceGrant — GEP-709 (#3, declaration: #166)
	{name: features.SupportReferenceGrant, requiresKind: "referencegrants"},
	// Standard: GRPCRoute — GEP-1016 (#33)
	{name: features.SupportGRPCRoute, requiresKind: pluralGRPCRoutes},
	// Extended: named route rules — GEP-995 (#504)
	{name: features.SupportGRPCRouteNamedRouteRule, requiresKind: pluralGRPCRoutes},
	// Standard: TLSRoute passthrough — GEP-2643 (#70)
	{name: features.SupportTLSRoute, requiresKind: pluralTLSRoutes},
	// Extended: TLSRoute terminate mode — #481
	{name: features.SupportTLSRouteModeTerminate, requiresKind: pluralTLSRoutes},
	// Extended: TLSRoute mixed (passthrough+terminate on same port) — #481
	{name: features.SupportTLSRouteModeMixed, requiresKind: pluralTLSRoutes},
	// Standard: TCPRoute — GEP-1901 (#505)
	{name: features.SupportTCPRoute, requiresKind: pluralTCPRoutes},
	// Standard: UDPRoute — GEP-2645 (#506)
	{name: features.SupportUDPRoute, requiresKind: pluralUDPRoutes},
	// Standard: ListenerSet — GEP-1713 (#93)
	{name: features.SupportListenerSet, requiresKind: pluralListenerSets},
	// Extended: Gateway infrastructure metadata propagation — GEP-1867 (#482).
	// spec.infrastructure.{labels,annotations} propagate onto provisioned
	// resources; in shared mode the carrier is a per-Gateway identity
	// ServiceAccount in the Gateway's namespace.
	{name: features.SupportGatewayInfrastructurePropagation},
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
		declared = append(declared, feature.name)
	}
	return declared
}
