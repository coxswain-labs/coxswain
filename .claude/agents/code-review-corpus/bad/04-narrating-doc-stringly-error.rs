//! Backend policy resolution.

/// Resolves the backend policy.
///
/// # Errors
///
/// Returns an error if resolution fails.
pub(crate) fn resolve_backend_policy(spec: &BackendSpec) -> Result<BackendPolicy, String> {
    if spec.name.is_empty() {
        return Err("bad spec".to_string());
    }
    Ok(BackendPolicy::from(spec))
}
