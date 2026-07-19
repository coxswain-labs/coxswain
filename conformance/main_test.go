package conformance_test

import (
	"os"
	"testing"

	v1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance"
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
	caps, err := detectCapabilities(t.Context())
	if err != nil {
		t.Fatalf("could not determine the cluster's Gateway API capabilities: %v", err)
	}

	opts := conformance.DefaultOptions(t)
	opts.GatewayClassName = "coxswain"

	// Profiles are constructed from strings, not from `suite.Gateway*ProfileName`
	// constants. `GatewayTCPConformanceProfileName` and its UDP sibling do not
	// exist in the Gateway API v1.4 Go module, so naming them would make this
	// file fail to *compile* against the suite version matching a v1.4 cluster —
	// which is exactly the configuration #641 exists to support.
	//
	// A profile is claimed only when the CRDs backing it are installed: the
	// suite runs every test in a claimed profile, and those tests create the
	// route kind.
	opts.ConformanceProfiles = profilesFor(caps)

	// Declare only features that are currently implemented AND that the
	// installed CRDs can express. Add entries here as each feature issue closes;
	// give an entry a `requires` guard when its CRD kind or schema field is
	// absent below Gateway API v1.6.
	opts.SupportedFeatures = supportedFeatures(caps)

	ipType := v1beta1.IPAddressType

	// GatewayStaticAddresses (#260, #558): the suite overlays these onto the
	// test's `PLACEHOLDER_USABLE_ADDRS`/`PLACEHOLDER_UNUSABLE_ADDRS` manifest
	// values. coxswain honors a requested IP by provisioning the Gateway's VIP as
	// a ClusterIP pinned to it, so the "usable" address must be a free IP inside
	// the cluster's Service CIDR (the apiserver assigns it exactly) — and from the
	// CIDR's static lower band, which random allocation never touches, so the
	// suite's own base-manifest Services can't steal it between injection and the
	// test run (#558). The "unusable" address is a TEST-NET-1 IP outside any
	// Service CIDR, which the apiserver rejects →
	// Programmed=False/AddressNotUsable. The CI run-conformance action and
	// scripts/setup-conformance.sh both select a free static-band clusterIP and
	// inject it via env so the usable IP tracks the live cluster.
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
