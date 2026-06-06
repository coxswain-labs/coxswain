pub mod backends;
pub mod gateway_api;
pub mod ingress;

use anyhow::Context as _;
use std::path::Path;
use tokio::io::AsyncWriteExt as _;

/// Template variables for [`apply_fixture`].
///
/// `TESTNS` is always replaced with `namespace`. The `http_port` and
/// `https_port` fields substitute `HTTP_PORT` and `HTTPS_PORT` respectively
/// when non-zero. Use [`FixtureVars::with`] to add extra substitutions.
pub struct FixtureVars {
    pub namespace: String,
    /// Substituted for `HTTP_PORT` in the YAML template. `0` means skip.
    pub http_port: u16,
    /// Substituted for `HTTPS_PORT` in the YAML template. `0` means skip.
    pub https_port: u16,
    pub extra: Vec<(String, String)>,
}

impl FixtureVars {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            http_port: 0,
            https_port: 0,
            extra: Vec::new(),
        }
    }

    pub fn with(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.extra.push((key.into(), val.into()));
        self
    }
}

/// Apply a fixture YAML file to `namespace` using `vars` for template substitution.
pub async fn apply_fixture(path: impl AsRef<Path>, vars: FixtureVars) -> anyhow::Result<()> {
    let path = path.as_ref();
    let mut content =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;

    // Apply extra vars first so callers can override the standard substitutions.
    for (key, val) in &vars.extra {
        content = content.replace(key.as_str(), val.as_str());
    }
    if vars.http_port != 0 {
        let p = vars.http_port.to_string();
        content = content.replace("HTTP_PORT", &p);
    }
    if vars.https_port != 0 {
        content = content.replace("HTTPS_PORT", &vars.https_port.to_string());
    }
    content = content.replace("TESTNS", &vars.namespace);

    let mut child = tokio::process::Command::new("kubectl")
        .args(["apply", "-n", &vars.namespace, "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("kubectl apply")?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(content.as_bytes())
            .await
            .context("write to kubectl stdin")?;
    }
    drop(child.stdin.take());

    let status = child.wait().await.context("kubectl wait")?;
    anyhow::ensure!(
        status.success(),
        "kubectl apply failed for {}",
        path.display()
    );
    Ok(())
}
