package conformance_test

// Drift: TCPRoute is advertised to the conformance suite but absent from the
// Rust table, so GatewayClass.status would never claim it.
var gatedFeatures = []gatedFeature{
	{name: "Gateway"},
	{name: "HTTPRouteCORS", requiresField: "HTTPRouteCORS"},
	{name: "TCPRoute", requiresKind: pluralTCPRoutes},
}
