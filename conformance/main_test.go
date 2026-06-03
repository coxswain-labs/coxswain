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
	opts.ConformanceProfiles = sets.New[suite.ConformanceProfileName](suite.GatewayHTTPConformanceProfileName)

	// Declare only features that are currently implemented.
	// Add entries here as each feature issue closes.
	opts.SupportedFeatures = sets.New[features.FeatureName](
		// Core (required for HTTP profile conformance claim)
		features.SupportGateway,   // #34
 		features.SupportHTTPRoute, // #34
		// Extended: matching (#7)
		features.SupportHTTPRouteQueryParamMatching,
		features.SupportHTTPRouteMethodMatching,
		// Extended: header modification (#13)
		// SupportHTTPRouteBackendRequestHeaderModification requires per-backend
		// filters + weighted routing; deferred to a future issue.
		features.SupportHTTPRouteResponseHeaderModification,
		// Extended: redirect and rewrite (#13)
		features.SupportHTTPRoutePortRedirect,
		features.SupportHTTPRouteSchemeRedirect,
		features.SupportHTTPRoutePathRedirect,
		features.SupportHTTPRouteHostRewrite,
		features.SupportHTTPRoutePathRewrite,
// 		// Extended: timeouts (#14)
// 		features.SupportHTTPRouteRequestTimeout,
// 		features.SupportHTTPRouteBackendTimeout,
// 		// Extended: websocket (#15 dependency, port mapping fix)
// 		features.SupportHTTPRouteBackendProtocolWebSocket,
	)

	conformance.RunConformanceWithOptions(t, opts)
}
