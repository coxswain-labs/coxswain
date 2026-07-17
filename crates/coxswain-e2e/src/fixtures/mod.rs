//! Fixture YAML path constants and the template-variable substitutor for `kubectl apply`.

pub mod backends;
pub mod dedicated_proxy;
pub mod gateway_api;
pub mod images;
pub mod ingress;

use crate::harness::{
    GATEWAY_HTTP_PORT, GATEWAY_HTTPS_PORT, INGRESS_HTTP_PORT, INGRESS_HTTPS_PORT,
    MALFORMED_AUTHZ_IMAGE,
};
use anyhow::Context as _;
use std::path::Path;
use tokio::io::AsyncWriteExt as _;

/// Template variables for [`apply_fixture`].
///
/// Placeholders are sentinel-delimited (`${NAME}`) so substitution can never
/// corrupt the document via substring collision: `${GATEWAY_HTTP_PORT}` is not a
/// superstring of `${HTTP_PORT}`, so order is irrelevant, and a bare prose mention
/// of a token name in a YAML comment is left untouched.
///
/// A fixed set of placeholders is always substituted by [`apply_fixture`],
/// regardless of fixture, so any test (with or without a [`Harness`]) gets the
/// same result: `${TESTNS}` (the namespace), the four in-cluster listener ports
/// (`${HTTP_PORT}`, `${HTTPS_PORT}`, `${GATEWAY_HTTP_PORT}`, `${GATEWAY_HTTPS_PORT}`),
/// and the pinned external images (`${ECHO_IMAGE}` etc., from the [`images`] module).
/// Placeholders absent from a given fixture are harmless no-ops.
///
/// Use [`FixtureVars::with`] for fixture-specific substitutions (hostnames, cert
/// bundles, resource names).
///
/// [`Harness`]: crate::harness::Harness
pub struct FixtureVars {
    /// Substituted for `${TESTNS}` in the YAML template.
    pub namespace: String,
    /// Additional `(placeholder, replacement)` pairs; `placeholder` is the bare
    /// token name (e.g. `"TLS_HOSTNAME"`), matched as `${TLS_HOSTNAME}` in the YAML.
    pub extra: Vec<(String, String)>,
}

impl FixtureVars {
    /// Construct a vars set scoped to `namespace`; the standard ports and images
    /// are injected by [`apply_fixture`] regardless.
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            extra: Vec::new(),
        }
    }

    /// Add an extra template substitution, returning `self` for chaining.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.extra.push((key.into(), val.into()));
        self
    }
}

/// Apply a fixture YAML file to `vars.namespace`, substituting template
/// placeholders, via `kubectl apply`.
///
/// This is the single fixture-apply path for the whole suite: it always injects
/// `${TESTNS}`, the in-cluster listener ports, and the pinned images, so it
/// behaves identically whether or not the caller holds a [`Harness`]. Tests that
/// manage their own [`ControllerProcess`] (to apply fixtures *before* the
/// controller starts) call it exactly like harness-based tests do.
///
/// [`Harness`]: crate::harness::Harness
/// [`ControllerProcess`]: crate::harness::ControllerProcess
///
/// # Errors
/// Returns an error if the fixture file can't be read or `kubectl apply` fails.
pub async fn apply_fixture(path: impl AsRef<Path>, vars: FixtureVars) -> anyhow::Result<()> {
    let path = path.as_ref();
    let content = prepare_fixture_content(path, vars)?;

    let mut child = tokio::process::Command::new("kubectl")
        .args(["apply", "-n", &content.1, "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("kubectl apply")?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(content.0.as_bytes())
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

/// Apply a fixture YAML file and assert that the API server **rejects** it.
///
/// Returns the combined error output from kubectl so the caller can assert on
/// the rejection message (e.g. that it mentions the expected annotation and
/// format). Fails the test if `kubectl apply` unexpectedly succeeds.
///
/// # Errors
/// Returns an error if the fixture file can't be read or `kubectl apply`
/// succeeds when rejection was expected.
pub async fn apply_fixture_expect_rejected(
    path: impl AsRef<Path>,
    vars: FixtureVars,
) -> anyhow::Result<String> {
    let path = path.as_ref();
    let (content, namespace) = prepare_fixture_content(path, vars)?;

    let mut child = tokio::process::Command::new("kubectl")
        .args(["apply", "-n", &namespace, "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("kubectl apply")?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(content.as_bytes())
            .await
            .context("write to kubectl stdin")?;
    }
    drop(child.stdin.take());

    let output = child.wait_with_output().await.context("kubectl wait")?;
    anyhow::ensure!(
        !output.status.success(),
        "expected kubectl apply to be rejected for {} but it succeeded",
        path.display()
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(format!("{stderr}{stdout}"))
}

/// Substitute template placeholders in `path` and return `(content, namespace)`.
fn prepare_fixture_content(path: &Path, vars: FixtureVars) -> anyhow::Result<(String, String)> {
    let mut content =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;

    // Sentinel-delimited (`${KEY}`) tokens make substitution order irrelevant —
    // `${GATEWAY_HTTP_PORT}` can no longer collide with `${HTTP_PORT}`.

    // Pinned external images: single source of truth in `images`.
    content = substitute(&content, "ECHO_IMAGE", images::ECHO);
    content = substitute(&content, "ECHO_UDP_IMAGE", images::ECHO_UDP);
    content = substitute(&content, "BUSYBOX_IMAGE", images::BUSYBOX);
    content = substitute(&content, "WEBSOCKET_ECHO_IMAGE", images::WEBSOCKET_ECHO);
    content = substitute(&content, "GO_HTTPBIN_IMAGE", images::GO_HTTPBIN);
    content = substitute(&content, "PEBBLE_IMAGE", images::PEBBLE);
    content = substitute(&content, "EXT_AUTHZ_IMAGE", images::EXT_AUTHZ);
    content = substitute(&content, "MALFORMED_AUTHZ_IMAGE", MALFORMED_AUTHZ_IMAGE);

    // Extra vars (caller-supplied, e.g. `${TLS_HOSTNAME}`, `${CA_PEM}`).
    for (key, val) in &vars.extra {
        content = substitute(&content, key, val);
    }

    // Fixed in-cluster listener ports — the harness port-forwards these.
    content = substitute(
        &content,
        "GATEWAY_HTTP_PORT",
        &GATEWAY_HTTP_PORT.to_string(),
    );
    content = substitute(
        &content,
        "GATEWAY_HTTPS_PORT",
        &GATEWAY_HTTPS_PORT.to_string(),
    );
    content = substitute(&content, "HTTP_PORT", &INGRESS_HTTP_PORT.to_string());
    content = substitute(&content, "HTTPS_PORT", &INGRESS_HTTPS_PORT.to_string());
    let namespace = vars.namespace.clone();
    content = substitute(&content, "TESTNS", &vars.namespace);

    Ok((content, namespace))
}

/// Replace every occurrence of the sentinel token `${key}` in `content` with
/// `val`, preserving the indentation prefix of the line containing each
/// occurrence on continuation lines of `val`.
///
/// `key` is the bare token name (e.g. `"TESTNS"`); the matched form is `${TESTNS}`.
/// Sentinel delimiting means a bare prose mention of the name in a comment is left
/// untouched, and tokens cannot collide by substring.
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
    let token = format!("${{{key}}}");
    if val.contains('\n') {
        substitute_indent_aware(content, &token, val)
    } else {
        // Single-line value: plain replace, identical to the historical behaviour.
        content.replace(&token, val)
    }
}

fn substitute_indent_aware(content: &str, token: &str, val: &str) -> String {
    let mut out = String::with_capacity(content.len() + val.len());
    let mut cursor = 0;
    while let Some(rel) = content[cursor..].find(token) {
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

        cursor = idx + token.len();
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
        let out = substitute("hostname: ${TLS_HOSTNAME}", "TLS_HOSTNAME", "example.com");
        assert_eq!(out, "hostname: example.com");
    }

    #[test]
    fn multi_line_value_in_yaml_block_scalar_keeps_indent() {
        let template = "data:\n  ca.crt: |\n    ${CA_PEM}\n";
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
        let out = substitute(template, "CA_PEM", pem);
        assert_eq!(
            out,
            "data:\n  ca.crt: |\n    -----BEGIN CERTIFICATE-----\n    AAAA\n    -----END CERTIFICATE-----\n"
        );
    }

    #[test]
    fn multi_line_value_inside_comment_stays_commented() {
        let template = "# Note: ${CA_PEM} is the bundle\n---\n";
        let pem = "first\nsecond";
        let out = substitute(template, "CA_PEM", pem);
        assert_eq!(out, "# Note: first\n# second is the bundle\n---\n");
    }

    #[test]
    fn multiple_occurrences_all_substituted() {
        let template = "  A: ${CA_PEM}\n  B: ${CA_PEM}\n";
        let pem = "one\ntwo";
        let out = substitute(template, "CA_PEM", pem);
        assert_eq!(out, "  A: one\n  two\n  B: one\n  two\n");
    }

    #[test]
    fn bare_token_name_without_sentinel_is_left_untouched() {
        // A prose mention of the token name (no `${}`) must not be substituted —
        // this is what keeps `# TESTNS is substituted at runtime` comments safe.
        let out = substitute("# TESTNS is substituted at runtime", "TESTNS", "ns-1");
        assert_eq!(out, "# TESTNS is substituted at runtime");
    }

    #[test]
    fn superstring_token_is_not_corrupted_by_substring_token() {
        // Order-independence: substituting `${HTTP_PORT}` must not touch
        // `${GATEWAY_HTTP_PORT}`.
        let template = "a: ${HTTP_PORT}\nb: ${GATEWAY_HTTP_PORT}\n";
        let out = substitute(template, "HTTP_PORT", "80");
        assert_eq!(out, "a: 80\nb: ${GATEWAY_HTTP_PORT}\n");
    }
}
