//! Fixture YAML path constants and the template-variable substitutor for `kubectl apply`.

pub mod backends;
pub mod dedicated_proxy;
pub mod gateway_api;
pub mod ingress;

use anyhow::Context as _;
use std::path::Path;
use tokio::io::AsyncWriteExt as _;

/// Template variables for [`apply_fixture`].
///
/// `TESTNS` is always replaced with `namespace`. The four port fields
/// substitute the placeholders below when non-zero:
///
/// - `http_port` → `HTTP_PORT` (Ingress HTTP listener)
/// - `https_port` → `HTTPS_PORT` (Ingress HTTPS listener)
/// - `gateway_http_port` → `GATEWAY_HTTP_PORT` (Gateway HTTP listener)
/// - `gateway_https_port` → `GATEWAY_HTTPS_PORT` (Gateway HTTPS listener)
///
/// `ingress_class` and `gateway_class` are always substituted for
/// `INGRESSCLASS` and `GATEWAYCLASS`, defaulting to `"coxswain"`.
/// Dedicated-release tests override these to their isolated class names.
///
/// Use [`FixtureVars::with`] to add extra substitutions.
pub struct FixtureVars {
    /// Substituted for `TESTNS` in the YAML template.
    pub namespace: String,
    /// Substituted for `HTTP_PORT` in the YAML template. `0` means skip.
    pub http_port: u16,
    /// Substituted for `HTTPS_PORT` in the YAML template. `0` means skip.
    pub https_port: u16,
    /// Substituted for `GATEWAY_HTTP_PORT` in the YAML template. `0` means skip.
    pub gateway_http_port: u16,
    /// Substituted for `GATEWAY_HTTPS_PORT` in the YAML template. `0` means skip.
    pub gateway_https_port: u16,
    /// Substituted for `INGRESSCLASS`. Defaults to `"coxswain"`.
    pub ingress_class: String,
    /// Substituted for `GATEWAYCLASS`. Defaults to `"coxswain"`.
    pub gateway_class: String,
    /// Additional `(placeholder, replacement)` pairs applied before the standard substitutions.
    pub extra: Vec<(String, String)>,
}

impl FixtureVars {
    /// Construct a minimal vars set with only a namespace (all ports default to 0 = skip).
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            http_port: 0,
            https_port: 0,
            gateway_http_port: 0,
            gateway_https_port: 0,
            ingress_class: "coxswain".into(),
            gateway_class: "coxswain".into(),
            extra: Vec::new(),
        }
    }

    /// Add an extra template substitution, returning `self` for chaining.
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
        content = substitute(&content, key, val);
    }
    // Class tokens: always substituted (default "coxswain"; dedicated tests override).
    // `GATEWAYCLASS` before `INGRESSCLASS` is arbitrary — neither is a substring
    // of the other. Both are applied before port tokens.
    content = substitute(&content, "GATEWAYCLASS", &vars.gateway_class);
    content = substitute(&content, "INGRESSCLASS", &vars.ingress_class);
    // Substitute Gateway placeholders before Ingress ones; `GATEWAY_HTTP_PORT`
    // is a superstring of `HTTP_PORT` and a literal-replace pass over `HTTP_PORT`
    // first would corrupt the Gateway placeholder.
    if vars.gateway_http_port != 0 {
        content = substitute(
            &content,
            "GATEWAY_HTTP_PORT",
            &vars.gateway_http_port.to_string(),
        );
    }
    if vars.gateway_https_port != 0 {
        content = substitute(
            &content,
            "GATEWAY_HTTPS_PORT",
            &vars.gateway_https_port.to_string(),
        );
    }
    if vars.http_port != 0 {
        let p = vars.http_port.to_string();
        content = substitute(&content, "HTTP_PORT", &p);
    }
    if vars.https_port != 0 {
        content = substitute(&content, "HTTPS_PORT", &vars.https_port.to_string());
    }
    content = substitute(&content, "TESTNS", &vars.namespace);

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

/// Replace every occurrence of `key` in `content` with `val`, preserving the
/// indentation prefix of the line containing each occurrence on continuation
/// lines of `val`.
///
/// The "indentation prefix" is the leading whitespace of the placeholder's line,
/// optionally extended with a leading `#` (and the whitespace immediately after it)
/// so that `val` substituted into a comment header stays inside the comment block
/// rather than producing bare-text lines that break YAML parsing.
///
/// This means callers can pass raw multi-line content (e.g. PEM bundles) and have
/// the substitution Just Work whether the placeholder is in a YAML block scalar,
/// a regular indented field, or a `#`-prefixed comment.
fn substitute(content: &str, key: &str, val: &str) -> String {
    if val.contains('\n') {
        substitute_indent_aware(content, key, val)
    } else {
        // Single-line value: plain replace, identical to the historical behaviour.
        content.replace(key, val)
    }
}

fn substitute_indent_aware(content: &str, key: &str, val: &str) -> String {
    let mut out = String::with_capacity(content.len() + val.len());
    let mut cursor = 0;
    while let Some(rel) = content[cursor..].find(key) {
        let idx = cursor + rel;
        // Append the chunk before the match.
        out.push_str(&content[cursor..idx]);

        // Compute the line prefix: leading whitespace plus an optional leading '#'
        // (with the whitespace that follows it) from the placeholder's line.
        let line_start = content[..idx].rfind('\n').map(|n| n + 1).unwrap_or(0);
        let line_head = &content[line_start..idx];
        let prefix = line_continuation_prefix(line_head);

        // Append the value with each continuation line carrying the prefix.
        let mut first = true;
        for line in val.split('\n') {
            if first {
                out.push_str(line);
                first = false;
            } else {
                out.push('\n');
                out.push_str(&prefix);
                out.push_str(line);
            }
        }

        cursor = idx + key.len();
    }
    out.push_str(&content[cursor..]);
    out
}

/// Compute the prefix to copy onto each continuation line of a multi-line value.
///
/// For a YAML body line like `    CA_PEM` the prefix is `"    "` (whitespace).
/// For a comment line like `# Note CA_PEM does …` the prefix is `"# "` so the
/// continuation lines remain part of the comment.
fn line_continuation_prefix(line_head: &str) -> String {
    let mut prefix = String::new();
    let mut chars = line_head.chars().peekable();
    // Capture leading whitespace.
    while let Some(&c) = chars.peek() {
        if c == ' ' || c == '\t' {
            prefix.push(c);
            chars.next();
        } else {
            break;
        }
    }
    // If the first non-whitespace char is '#', capture it plus the single space
    // that conventionally follows so continuation lines look like normal comment text.
    if chars.peek().copied() == Some('#') {
        prefix.push('#');
        chars.next();
        if chars.peek().copied() == Some(' ') {
            prefix.push(' ');
        }
    }
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_line_value_round_trips() {
        let out = substitute("hostname: TLS_HOSTNAME", "TLS_HOSTNAME", "example.com");
        assert_eq!(out, "hostname: example.com");
    }

    #[test]
    fn multi_line_value_in_yaml_block_scalar_keeps_indent() {
        let template = "data:\n  ca.crt: |\n    CA_PEM\n";
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
        let out = substitute(template, "CA_PEM", pem);
        assert_eq!(
            out,
            "data:\n  ca.crt: |\n    -----BEGIN CERTIFICATE-----\n    AAAA\n    -----END CERTIFICATE-----\n"
        );
    }

    #[test]
    fn multi_line_value_inside_comment_stays_commented() {
        let template = "# Note: CA_PEM is the bundle\n---\n";
        let pem = "first\nsecond";
        let out = substitute(template, "CA_PEM", pem);
        assert_eq!(out, "# Note: first\n# second is the bundle\n---\n");
    }

    #[test]
    fn multiple_occurrences_all_substituted() {
        let template = "  A: CA_PEM\n  B: CA_PEM\n";
        let pem = "one\ntwo";
        let out = substitute(template, "CA_PEM", pem);
        assert_eq!(out, "  A: one\n  two\n  B: one\n  two\n");
    }
}
