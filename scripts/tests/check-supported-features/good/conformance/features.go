package conformance_test

var gatedFeatures = []gatedFeature{
	{name: "Gateway"},
	{name: "HTTPRouteCORS", requiresField: "HTTPRouteCORS"},
}

// A commented-out declaration must not count as declared.
// {name: "TCPRoute", requiresKind: pluralTCPRoutes},
