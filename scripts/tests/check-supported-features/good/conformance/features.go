package conformance_test

var gatedFeatures = []gatedFeature{
	{name: features.SupportGateway},
	{name: features.SupportHTTPRouteCORS, requiresField: "HTTPRouteCORS"},
}

// A commented-out declaration must not count as declared.
// {name: features.SupportTCPRoute, requiresKind: pluralTCPRoutes},
