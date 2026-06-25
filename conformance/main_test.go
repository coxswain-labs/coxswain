package conformance_test

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

// TestConformance runs the Gateway API HTTP conformance suite against Coxswain.
//
// Required flags (passed via -args):
//
//	--organization=coxswain-labs
//	--project=coxswain
//	--url=https://github.com/coxswain-labs/coxswain
//	--version=<git-describe>
//	--report-output=reports/<file>.yaml
//
// The cluster must have:
//   - Gateway API CRDs installed
//   - GatewayClass "coxswain" created
//   - Coxswain running with --status-address set to the reachable proxy IP
func TestConformance(t *testing.T) {
	opts := conformance.DefaultOptions(t)
	opts.GatewayClassName = "coxswain"
	opts.ConformanceProfiles = sets.New[suite.ConformanceProfileName](
		suite.GatewayHTTPConformanceProfileName,
		suite.GatewayGRPCConformanceProfileName,
	)

	// Declare only features that are currently implemented.
	// Add entries here as each feature issue closes.
	opts.SupportedFeatures = sets.New[features.FeatureName](
		// Core (required for HTTP profile conformance claim)
		features.SupportGateway,   // #34
 		features.SupportHTTPRoute, // #34
		// Extended: matching (#7)
		features.SupportHTTPRouteQueryParamMatching,
		features.SupportHTTPRouteMethodMatching,
		// Extended: header modification (#13, #167)
		features.SupportHTTPRouteBackendRequestHeaderModification,
		features.SupportHTTPRouteResponseHeaderModification,
		// Extended: redirect and rewrite (#13)
		features.SupportHTTPRoutePortRedirect,
		features.SupportHTTPRouteSchemeRedirect,
		features.SupportHTTPRoutePathRedirect,
		features.SupportHTTPRouteHostRewrite,
		features.SupportHTTPRoutePathRewrite,
		// Extended: timeouts (#14)
		features.SupportHTTPRouteRequestTimeout,
		features.SupportHTTPRouteBackendTimeout,
		// Extended: redirect status codes (#34)
		features.SupportHTTPRoute303RedirectStatusCode,
		features.SupportHTTPRoute307RedirectStatusCode,
		features.SupportHTTPRoute308RedirectStatusCode,
		// Extended: named route rules (#34)
		features.SupportHTTPRouteNamedRouteRule,
		// Extended: HTTP listener isolation (#34)
		features.SupportGatewayHTTPListenerIsolation,
		// Extended: CORS filter — GEP-1767 (#41)
		features.SupportHTTPRouteCORS,
		// Extended: RequestMirror filter — GEP-3171 (#261)
		features.SupportHTTPRouteRequestMirror,
		features.SupportHTTPRouteRequestMultipleMirrors,
		features.SupportHTTPRouteRequestPercentageMirror,
		// Extended: HTTPS misdirected-request detection — GEP-3567 (#96)
		features.SupportGatewayHTTPSListenerDetectMisdirectedRequests,
		// Extended: port 8080 listener (#34)
		features.SupportGatewayPort8080,
		// Extended: empty Gateway address value (#34)
		features.SupportGatewayAddressEmpty,
		// Extended: parentRef port mismatch → NoMatchingParent (#34)
		features.SupportHTTPRouteDestinationPortMatching,
		// Extended: per-port listener routing (#82, #98)
		features.SupportHTTPRouteParentRefPort,
		// Extended: backend protocol selection — GEP-1911 (#90, #32)
		features.SupportHTTPRouteBackendProtocolH2C,
		features.SupportHTTPRouteBackendProtocolWebSocket,
		// Core: BackendTLSPolicy — GEP-1897 (#16)
		// SupportBackendTLSPolicySANValidation is Extended and not yet implemented.
		features.SupportBackendTLSPolicy,
		// Standard: ReferenceGrant — GEP-709 (#3, declaration: #166)
		// Implementation in coxswain-core/src/reference_grants.rs is already complete;
		// previously omitted from the SupportedFeatures set, so the GatewayClass status
		// did not advertise it. This declaration is paperwork only.
		features.SupportReferenceGrant,
		// Standard: GRPCRoute — GEP-1016 (#33)
		features.SupportGRPCRoute,
	)

	conformance.RunConformanceWithOptions(t, opts)
}
