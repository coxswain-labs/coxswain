//! Core.
use crate::routing::compile_bounded;
fn compile(p: &str) -> Result<Regex, Error> { compile_bounded(p) }
