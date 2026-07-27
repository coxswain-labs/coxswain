//! Discovery.
fn compile(p: &str) -> Result<Regex, Error> {
    // Untrusted wire input recompiled with the 10 MB default size_limit.
    Regex::new(p).map_err(Into::into)
}
