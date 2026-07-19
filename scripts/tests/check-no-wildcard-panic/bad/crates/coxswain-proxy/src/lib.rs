//! Proxy.
fn map(o: Outcome) -> u16 {
    match o {
        Outcome::Found => 200,
        _ => panic!("unhandled outcome"),
    }
}
