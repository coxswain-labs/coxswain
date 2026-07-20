//go:build gwapi_profiles_set

package conformance_test

import (
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

// applyProfiles and applyFeatures assign the claimed profiles and declared
// features for Gateway API v1.4 and v1.5, where both option fields are sets.
//
// See the sibling file for why this is a build-tag split rather than a runtime
// branch: the fields' container types changed at v1.6.
func applyProfiles(opts *suite.ConformanceOptions, names []suite.ConformanceProfileName) {
	opts.ConformanceProfiles = sets.New(names...)
}

func applyFeatures(opts *suite.ConformanceOptions, names []features.FeatureName) {
	opts.SupportedFeatures = sets.New(names...)
}
