package conformance_test

import (
	"os"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
	v1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
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
		suite.GatewayTLSConformanceProfileName,
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
		// Extended: static Gateway addresses — GatewayStaticAddresses (#260).
		// Coxswain honors a requested IPAddress by pinning it as the per-Gateway
		// VIP Service clusterIP (deterministic accept/reject vs the apiserver
		// service-CIDR). Requires UsableNetworkAddresses/UnusableNetworkAddresses
		// below, injected by scripts/setup-conformance.sh.
		features.SupportGatewayStaticAddresses,
		// Standard: backend client-certificate (mTLS to upstream) — GEP-3155 (#87)
		features.SupportGatewayBackendClientCertificate,
		// Standard: frontend client-certificate validation — GEP-91 (#86)
		features.SupportGatewayFrontendClientCertificateValidation,
		features.SupportGatewayFrontendClientCertificateValidationInsecureFallback,
		// Extended: parentRef port mismatch → NoMatchingParent (#34)
		features.SupportHTTPRouteDestinationPortMatching,
		// Extended: per-port listener routing (#82, #98)
		features.SupportHTTPRouteParentRefPort,
		// Extended: backend protocol selection — GEP-1911 (#90, #32)
		features.SupportHTTPRouteBackendProtocolH2C,
		features.SupportHTTPRouteBackendProtocolWebSocket,
		// Core: BackendTLSPolicy — GEP-1897 (#16)
		// Extended: BackendTLSPolicy subjectAltNames — GEP-1897 (#133)
		features.SupportBackendTLSPolicy,
		features.SupportBackendTLSPolicySANValidation,
		// Standard: ReferenceGrant — GEP-709 (#3, declaration: #166)
		// Implementation in coxswain-core/src/reference_grants.rs is already complete;
		// previously omitted from the SupportedFeatures set, so the GatewayClass status
		// did not advertise it. This declaration is paperwork only.
		features.SupportReferenceGrant,
		// Standard: GRPCRoute — GEP-1016 (#33)
		features.SupportGRPCRoute,
		// Standard: TLSRoute passthrough — GEP-2643 (#70)
		features.SupportTLSRoute,
		// Extended: TLSRoute terminate mode — #481
		features.SupportTLSRouteModeTerminate,
		// Extended: TLSRoute mixed (passthrough+terminate on same port) — #481
		features.SupportTLSRouteModeMixed,
		// Standard: ListenerSet — GEP-1713 (#93)
		features.SupportListenerSet,
		// Extended: Gateway infrastructure metadata propagation — GEP-1867 (#482).
		// spec.infrastructure.{labels,annotations} propagate onto provisioned
		// resources; in shared mode the carrier is a per-Gateway identity
		// ServiceAccount in the Gateway's namespace.
		features.SupportGatewayInfrastructurePropagation,
	)

	// GatewayStaticAddresses (#260): the suite overlays these onto the test's
	// `PLACEHOLDER_USABLE_ADDRS`/`PLACEHOLDER_UNUSABLE_ADDRS` manifest values.
	// coxswain honors a requested IP by provisioning the Gateway's VIP as a
	// ClusterIP pinned to it, so the "usable" address must be a free IP inside the
	// cluster's Service CIDR (the apiserver assigns it exactly); the "unusable"
	// address is a TEST-NET-1 IP outside any Service CIDR, which the apiserver
	// rejects → Programmed=False/AddressNotUsable. The CI run-conformance action
	// and scripts/setup-conformance.sh both probe a free clusterIP and inject it
	// via env so the usable IP tracks the live cluster.
	ipType := v1beta1.IPAddressType
	usable := os.Getenv("CONFORMANCE_USABLE_ADDR")
	unusable := os.Getenv("CONFORMANCE_UNUSABLE_ADDR")
	if usable != "" && unusable != "" {
		opts.UsableNetworkAddresses = []v1beta1.GatewaySpecAddress{
			{Type: &ipType, Value: usable},
		}
		opts.UnusableNetworkAddresses = []v1beta1.GatewaySpecAddress{
			{Type: &ipType, Value: unusable},
		}
	} else {
		// Without an injected address pool the manifest's placeholder addresses
		// are stripped and the test's "expected 3 addresses" precondition fails.
		// CI and setup-conformance.sh always set the env; this skip covers a bare
		// `go test` run started without the probe. The feature stays advertised on
		// GatewayClass and is covered by the by-plane e2e suite either way.
		opts.SkipTests = append(opts.SkipTests, "GatewayStaticAddresses")
	}

	conformance.RunConformanceWithOptions(t, opts)
}
