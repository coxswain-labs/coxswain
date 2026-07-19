//! Core.
fn compile(p: &str) -> Result<Regex, Error> {
    // 10 MB default size_limit on attacker-supplied input.
    Regex::new(p).map_err(Into::into)
}
