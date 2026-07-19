package conformance_test

// Drift: TCPRoute is advertised to the conformance suite but absent from the
// Rust table, so GatewayClass.status would never claim it. This is the exact
// shape of the mismatch the gate exists to catch.
var gatedFeatures = []gatedFeature{
	{name: features.SupportGateway},
	{name: features.SupportHTTPRouteCORS, requiresField: "HTTPRouteCORS"},
	{name: features.SupportTCPRoute, requiresKind: pluralTCPRoutes},
}
