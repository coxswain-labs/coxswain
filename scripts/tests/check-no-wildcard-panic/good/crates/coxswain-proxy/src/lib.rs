//! Proxy.
fn map(o: Outcome) -> u16 {
    match o {
        Outcome::Found => 200,
        other => {
            tracing::warn!(?other, "unhandled outcome; degrading");
            503
        }
    }
}
