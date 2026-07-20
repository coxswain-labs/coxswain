//go:build !gwapi_profiles_set

package conformance_test

import (
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

// applyProfiles and applyFeatures assign the claimed profiles and declared
// features for Gateway API v1.6+, where both option fields are slices.
//
// Two fields on `ConformanceOptions` changed container type across the versions
// Coxswain supports — `ConformanceProfiles` and `SupportedFeatures` were
// `sets.Set`-shaped through v1.5 and became slices at v1.6. String aliasing
// solves the *name* constants (see features.go) but cannot solve a
// container-type change, so these two assignments are selected by build tag.
// `scripts/run-conformance.sh` and the CI action pass `-tags gwapi_profiles_set`
// for v1.4/v1.5.
func applyProfiles(opts *suite.ConformanceOptions, names []suite.ConformanceProfileName) {
	opts.ConformanceProfiles = names
}

func applyFeatures(opts *suite.ConformanceOptions, names []features.FeatureName) {
	opts.SupportedFeatures = names
}
