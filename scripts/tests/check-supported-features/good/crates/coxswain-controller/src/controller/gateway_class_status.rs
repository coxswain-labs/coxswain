// Miniature stand-in for the real table. Only the shape the gate parses
// matters: a `SUPPORTED_FEATURES` table of `("Name", Requirement)` entries,
// including one rustfmt has split across lines.
pub(super) const SUPPORTED_FEATURES: &[(&str, Requirement)] = &[
    ("Gateway", Kind(GatewayApiKind::Gateway)),
    (
        "HTTPRouteCORS",
        Field(GatewayApiField::HttpRouteCors),
    ),
];

// A quoted string outside the table must not be picked up as a feature.
const UNRELATED: &str = "NotAFeature";
