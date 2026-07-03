//! Code generator for `gateway-api-types` (#510).
//!
//! Fetches Gateway API CRD schemas and Go condition-constant source from
//! `kubernetes-sigs/gateway-api` at the tag pinned in the repo-root
//! `.gateway-api-version` file, and emits `crates/gateway-api-types/src/apis/**`
//! and `crates/gateway-api-types/src/constants.rs`. Nothing in the generated
//! crate is hand-maintained: CRD kinds, condition constants, and per-enum
//! `Default` impls are all discovered or derived from the pinned tag, so a
//! spec bump can't silently drift out of sync the way upstream's hand-curated
//! tables did.
//!
//! Regenerate with `cargo run -p xtask -- gateway-api-types`, or
//! `cargo run -p xtask -- gateway-api-types <tag>` to test an
//! unreleased tag without touching `.gateway-api-version`.
//!
//! Requires the `kopium` CLI (`cargo install kopium`) and an authenticated
//! `gh` CLI — the GitHub REST API (not just anonymous `raw.githubusercontent.com`
//! fetches) is what lets CRD-kind and Go-source discovery work off a directory
//! listing instead of a hand-maintained list.

#![deny(unsafe_code)]
#![warn(clippy::all, rust_2018_idioms)]

use std::{
    collections::{BTreeMap, HashSet},
    env,
    fmt::Write as _,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use serde::Deserialize;

/// Upstream repo this generator pulls CRD schemas and Go condition source from.
const REPO: &str = "kubernetes-sigs/gateway-api";

/// Directory under the upstream repo holding per-channel CRD manifests
/// (`config/crd/standard/*.yaml`, `config/crd/experimental/*.yaml`).
const CRD_DIR_PREFIX: &str = "config/crd/";

/// `kopium` invocation shared by every CRD kind.
const KOPIUM_ARGS: &[&str] = &[
    "--schema=derived",
    "--derive=JsonSchema",
    "--derive=Default",
    "--derive=PartialEq",
    "--docs",
    "-f",
    "-",
];

/// Known Gateway API group-name prefixes on CRD manifest filenames
/// (`gateway.networking.k8s.io_gateways.yaml`,
/// `gateway.networking.x-k8s.io_xbackends.yaml`). Used only to recover the
/// module name from a filename the tree listing already discovered — never
/// to hand-list which kinds exist.
const GROUP_PREFIXES: &[&str] = &["gateway.networking.k8s.io_", "gateway.networking.x-k8s.io_"];

/// Go package trees treated as the canonical source of condition constants.
///
/// `apis/v1alpha2`, `apis/v1alpha3`, and `apis/v1beta1` are back-compat
/// mirrors of `apis/v1`: some are pure Go type aliases (`type X = v1.X`,
/// which our regex naturally skips — no `= "value"` to match) and others
/// re-declare a strict subset of `apis/v1`'s constants under the same
/// identifiers. Scanning them adds no information `apis/v1` doesn't already
/// have. `apisx/v1alpha1` is a *separate* Go module tree (the "x-" prefixed
/// experimental kinds — XBackend, XBackendTrafficPolicy, XMesh) with its own
/// condition consts (e.g. `MeshConditionType`) that a plain `apis/**` scan
/// would miss entirely, since `apisx` isn't under `apis`.
const CONDITION_SOURCE_DIRS: &[&str] = &["apis/v1/", "apisx/v1alpha1/"];

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gateway-api-types") => generate(args.get(2).map(String::as_str)),
        _ => {
            eprintln!("usage: cargo run -p xtask -- gateway-api-types [version]");
            std::process::exit(1);
        }
    }
}

// -----------------------------------------------------------------------------
// Orchestration
// -----------------------------------------------------------------------------

fn generate(version_override: Option<&str>) -> Result<()> {
    let root = repo_root()?;
    let version = resolve_version(&root, version_override)?;
    eprintln!("generating gateway-api-types against {version}");

    let tree = fetch_tree(&version)?;
    let crds = classify_crds(&version, &tree)?;
    if crds.is_empty() {
        bail!("no CRD manifests discovered under {CRD_DIR_PREFIX} at {version}");
    }
    let conditions = fetch_conditions(&version, &tree)?;

    let crate_dir = root.join("crates/gateway-api-types");
    let apis_dir = crate_dir.join("src/apis");

    // Fixed, not discovered: these are the two channel directory names
    // upstream's own repo layout defines (config/crd/{standard,experimental}).
    // Only channels actually present in this tag's tree are emitted.
    let mut channels = Vec::new();
    for channel in ["standard", "experimental"] {
        if let Some(channel_crds) = crds.get(channel) {
            generate_channel(&apis_dir, channel, channel_crds)?;
            channels.push(channel.to_string());
        }
    }

    write_apis_mod(&apis_dir, &channels)?;
    write_constants(&crate_dir.join("src/constants.rs"), &conditions)?;
    cargo_fmt(&root)?;

    eprintln!(
        "done: {} channel(s), {} condition enum(s)",
        channels.len(),
        conditions.len()
    );
    Ok(())
}

/// Repo root, resolved from this crate's manifest directory — `xtask` is a
/// repo-root sibling of `crates/`, the classic `cargo xtask` layout (matching
/// upstream `gateway-api-rs`'s own `xtask/` next to `gateway-api/`), not a
/// nested member of the production `crates/*` tree.
fn repo_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("xtask must be a repo-root sibling of crates/"))
}

/// The Gateway API tag to generate against: an explicit CLI override, or the
/// repo-root `.gateway-api-version` file — the single version knob shared
/// with `scripts/setup-conformance.sh` and `coxswain-e2e`'s bootstrap harness.
fn resolve_version(root: &Path, version_override: Option<&str>) -> Result<String> {
    if let Some(v) = version_override {
        return Ok(v.to_string());
    }
    let path = root.join(".gateway-api-version");
    let raw =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(raw.trim().to_string())
}

// -----------------------------------------------------------------------------
// GitHub tree discovery
// -----------------------------------------------------------------------------

#[derive(Deserialize)]
struct TreeResponse {
    tree: Vec<TreeItem>,
    /// GitHub sets this when the tree exceeded the API's recursive-listing
    /// cap (~100k entries / ~7MB) and silently dropped entries — must be
    /// checked, or a spec bump past that size would fail exactly the
    /// silent-omission failure mode this generator exists to prevent.
    #[serde(default)]
    truncated: bool,
}

#[derive(Deserialize)]
struct TreeItem {
    path: String,
    #[serde(rename = "type")]
    kind: String,
}

/// Lists every file in the repo at `version`, via one `gh api` call. This is
/// what lets CRD-kind and Go-source discovery work off the tag's actual
/// contents instead of a hand-maintained list that silently misses additions
/// like GEP-91's `XBackend` or a new `apisx` package.
fn fetch_tree(version: &str) -> Result<Vec<TreeItem>> {
    let output = Command::new("gh")
        .args([
            "api",
            &format!("repos/{REPO}/git/trees/{version}?recursive=1"),
        ])
        .output()
        .context("failed to run `gh api` — is the gh CLI installed and authenticated?")?;
    if !output.status.success() {
        bail!(
            "gh api tree listing for {version} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let parsed: TreeResponse =
        serde_json::from_slice(&output.stdout).context("failed to parse gh api tree response")?;
    if parsed.truncated {
        bail!(
            "gh api tree listing for {version} was truncated by GitHub (repo tree exceeds the \
             recursive-listing size cap) — CRD-kind and Go-source discovery would silently miss \
             entries past the cutoff; this generator cannot proceed on a truncated listing"
        );
    }
    Ok(parsed
        .tree
        .into_iter()
        .filter(|i| i.kind == "blob")
        .collect())
}

fn fetch_raw(version: &str, path: &str) -> Result<String> {
    let url = format!("https://raw.githubusercontent.com/{REPO}/{version}/{path}");
    ureq::get(&url)
        .call()
        .with_context(|| format!("failed to fetch {url}"))?
        .into_body()
        .read_to_string()
        .with_context(|| format!("failed to read response body from {url}"))
}

// -----------------------------------------------------------------------------
// CRD discovery and classification
// -----------------------------------------------------------------------------

/// One discovered CRD manifest, already fetched (its content is needed both
/// to confirm `kind: CustomResourceDefinition` and to feed kopium, so it's
/// fetched once and carried along rather than re-fetched per use).
struct CrdSource {
    /// Module name, e.g. `"gatewayclasses"` — recovered by stripping the
    /// filename's own API-group prefix, never hand-listed.
    api_name: String,
    /// Full repo-relative path, e.g.
    /// `"config/crd/standard/gateway.networking.k8s.io_gateways.yaml"`.
    path: String,
    content: String,
}

/// Walks the tree once, fetching every `config/crd/{channel}/*.yaml` file and
/// keeping only those whose own YAML declares `kind: CustomResourceDefinition`
/// — this is what drops the `ValidatingAdmissionPolicy` and `kustomization.yaml`
/// files that also live in that directory, without hand-listing which
/// filenames to skip.
fn classify_crds(version: &str, tree: &[TreeItem]) -> Result<BTreeMap<String, Vec<CrdSource>>> {
    let mut by_channel: BTreeMap<String, Vec<CrdSource>> = BTreeMap::new();

    for item in tree {
        let Some(rest) = item.path.strip_prefix(CRD_DIR_PREFIX) else {
            continue;
        };
        let Some((channel, filename)) = rest.split_once('/') else {
            continue;
        };
        if !filename.ends_with(".yaml") {
            continue;
        }

        let content = fetch_raw(version, &item.path)?;

        // Some files in this directory (e.g. a VAP safe-upgrades manifest) are
        // multi-document YAML; only the first document's `kind` needs
        // checking to decide whether this file is a CRD at all.
        let Some(first_doc) = serde_yaml::Deserializer::from_str(&content).next() else {
            continue;
        };
        let doc = serde_yaml::Value::deserialize(first_doc)
            .with_context(|| format!("{}: not valid YAML", item.path))?;
        if doc.get("kind").and_then(serde_yaml::Value::as_str) != Some("CustomResourceDefinition") {
            continue;
        }

        let Some(api_name) = GROUP_PREFIXES
            .iter()
            .find_map(|prefix| filename.strip_prefix(prefix))
            .map(|s| s.trim_end_matches(".yaml").to_string())
        else {
            bail!(
                "{}: filename doesn't match a known Gateway API group prefix ({GROUP_PREFIXES:?})",
                item.path
            );
        };

        by_channel
            .entry(channel.to_string())
            .or_default()
            .push(CrdSource {
                api_name,
                path: item.path.clone(),
                content,
            });
    }

    // Deterministic, tag-independent module order — the GitHub tree API's
    // own ordering isn't a documented contract to regenerate byte-stable
    // output against.
    for sources in by_channel.values_mut() {
        sources.sort_by(|a, b| a.api_name.cmp(&b.api_name));
    }

    Ok(by_channel)
}

// -----------------------------------------------------------------------------
// Per-channel generation
// -----------------------------------------------------------------------------

fn generate_channel(apis_dir: &Path, channel: &str, crds: &[CrdSource]) -> Result<()> {
    let dir = apis_dir.join(channel);
    if dir.exists() {
        fs::remove_dir_all(&dir).with_context(|| format!("failed to clean {}", dir.display()))?;
    }
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;

    let mut api_names = Vec::with_capacity(crds.len());
    for crd in crds {
        eprintln!("generating {channel} api {}", crd.api_name);
        let generated = run_kopium(&crd.content)
            .with_context(|| format!("kopium failed for {channel}/{}", crd.api_name))?;
        let with_defaults = append_enum_defaults(&generated);
        let with_header = prepend_header(
            &with_defaults,
            &[
                format!(
                    "Generated by kopium from the {channel}-channel Gateway API CRD at `{}`.",
                    crd.path
                ),
                "Do not edit by hand — regenerate with `cargo run -p xtask -- gateway-api-types`."
                    .to_string(),
            ],
        );
        fs::write(dir.join(format!("{}.rs", crd.api_name)), with_header)
            .with_context(|| format!("failed to write {}/{}.rs", dir.display(), crd.api_name))?;
        api_names.push(crd.api_name.as_str());
    }

    fs::write(dir.join("mod.rs"), gen_channel_mod_rs(&api_names))
        .with_context(|| format!("failed to write {}/mod.rs", dir.display()))
}

fn run_kopium(crd_yaml: &str) -> Result<String> {
    let mut child = Command::new("kopium")
        .args(KOPIUM_ARGS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn kopium — install with `cargo install kopium`")?;

    {
        let mut stdin = child.stdin.take().ok_or_else(|| {
            anyhow!("kopium child process has no stdin pipe (spawned with Stdio::piped())")
        })?;
        stdin
            .write_all(crd_yaml.as_bytes())
            .context("failed to write CRD YAML to kopium stdin")?;
    }

    let output = child
        .wait_with_output()
        .context("kopium did not exit cleanly")?;
    if !output.status.success() {
        bail!(
            "kopium exited with an error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).context("kopium produced non-UTF-8 output")
}

/// Prepends a `//!` module header — required by `scripts/check-module-headers.sh`
/// and kopium's own header is a plain `//` comment, not `//!`.
fn prepend_header(body: &str, doc_lines: &[String]) -> String {
    let mut out = String::new();
    for line in doc_lines {
        let _ = writeln!(out, "//! {line}");
    }
    out.push('\n');
    out.push_str(body);
    out
}

// -----------------------------------------------------------------------------
// enum_defaults: post-process kopium's own output
// -----------------------------------------------------------------------------

/// For every `pub enum X { A, ... }` kopium emits, appends `impl Default for X`
/// using the first listed variant — kopium never derives `Default` on enums
/// (only on structs, via `#[kube(derive = "Default")]`/`#[derive(Default)]`),
/// so any enum reachable as a non-`Option` field of a `Default`-deriving
/// struct needs one. Blanket coverage (every enum, not just the ones
/// strictly load-bearing for some struct's derive) is simpler than tracking
/// which enums need it and equally correct — an unused `impl Default` is
/// inert. This is what replaces upstream's hand-maintained
/// `(EnumName, DefaultVariant)` list: it cannot silently omit a new enum a
/// spec bump introduces, because it never enumerates enums by name at all.
fn append_enum_defaults(generated: &str) -> String {
    let lines: Vec<&str> = generated.lines().collect();
    let mut out = String::from(generated);
    if !out.ends_with('\n') {
        out.push('\n');
    }

    for (i, raw) in lines.iter().enumerate() {
        let Some(rest) = raw.trim_start().strip_prefix("pub enum ") else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let Some(first_variant) = first_enum_variant(&lines[i + 1..]) else {
            continue;
        };
        let _ = write!(
            out,
            "\nimpl Default for {name} {{\n    fn default() -> Self {{\n        {name}::{first_variant}\n    }}\n}}\n"
        );
    }

    out
}

/// Scans lines following a `pub enum X {` declaration for the first unit
/// variant, skipping doc comments (`///`) and attributes (`#[...]`) kopium
/// emits per-variant.
///
/// Handles kopium's raw-identifier variants (`r#_301,` for a numeric-looking
/// CRD enum value like an HTTP redirect status code): the `r#` prefix is part
/// of the real identifier and must be preserved in the returned name, or the
/// generated `impl Default` would reference a nonexistent bare `r` variant.
fn first_enum_variant(lines: &[&str]) -> Option<String> {
    for raw in lines {
        let l = raw.trim();
        if l.is_empty() || l.starts_with("///") || l.starts_with("//") || l.starts_with('#') {
            continue;
        }
        if l.starts_with('}') {
            return None;
        }
        let (prefix, rest) = l.strip_prefix("r#").map_or(("", l), |rest| ("r#", rest));
        let ident: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        return if ident.is_empty() {
            None
        } else {
            Some(format!("{prefix}{ident}"))
        };
    }
    None
}

fn gen_channel_mod_rs(api_names: &[&str]) -> String {
    let mut out = String::from(
        "//! Aggregates this channel's generated kind modules.\n\
         //! Regenerate with `cargo run -p xtask -- gateway-api-types` — do not edit by hand.\n\n",
    );
    for name in api_names {
        let _ = writeln!(out, "pub mod {name};");
    }
    out
}

fn write_apis_mod(apis_dir: &Path, channels: &[String]) -> Result<()> {
    let mut out = String::from(
        "//! Aggregates the `standard` and (feature-gated) `experimental` Gateway API channels.\n\
         //! Regenerate with `cargo run -p xtask -- gateway-api-types` — do not edit by hand.\n\n",
    );
    for channel in channels {
        if channel == "experimental" {
            out.push_str("#[cfg(feature = \"experimental\")]\n");
        }
        let _ = writeln!(out, "pub mod {channel};");
    }
    fs::write(apis_dir.join("mod.rs"), out).context("failed to write apis/mod.rs")
}

// -----------------------------------------------------------------------------
// constants.rs: condition Type/Reason enums parsed from upstream Go source
// -----------------------------------------------------------------------------

/// Fetches every `*_types.go` file under [`CONDITION_SOURCE_DIRS`] and parses
/// condition `Type`/`Reason` constants out of them.
fn fetch_conditions(version: &str, tree: &[TreeItem]) -> Result<BTreeMap<String, Vec<String>>> {
    let mut sources = Vec::new();
    for item in tree {
        let matches_dir = CONDITION_SOURCE_DIRS
            .iter()
            .any(|dir| item.path.starts_with(dir));
        if matches_dir && item.path.ends_with("_types.go") {
            let content = fetch_raw(version, &item.path)?;
            sources.push((item.path.clone(), content));
        }
    }
    if sources.is_empty() {
        bail!(
            "no *_types.go files found under {CONDITION_SOURCE_DIRS:?} at {version} — has the Gateway API repo layout changed?"
        );
    }
    parse_conditions(&sources)
}

/// Extracts `Name Type = "Value"` const declarations for every
/// `*ConditionType`/`*ConditionReason` type, e.g.
/// `GatewayConditionProgrammed GatewayConditionType = "Programmed"` yields
/// `("GatewayConditionType", "Programmed")`. Go type ALIASES
/// (`type GatewayConditionType = v1.GatewayConditionType`) have no `= "..."`
/// and are naturally skipped — no separate alias-detection needed.
fn parse_conditions(sources: &[(String, String)]) -> Result<BTreeMap<String, Vec<String>>> {
    let re =
        Regex::new(r#"(?m)^[ \t]*\w+[ \t]+(\w+Condition(?:Type|Reason))[ \t]*=[ \t]*"([^"]+)""#)
            .context("condition regex failed to compile (this is a bug in the pattern literal)")?;

    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for (path, content) in sources {
        for caps in re.captures_iter(content) {
            let type_name = caps[1].to_string();
            let value = caps[2].to_string();
            if !is_valid_ident(&value) {
                bail!(
                    "{path}: condition value {value:?} for {type_name} is not a valid Rust identifier"
                );
            }
            if seen.insert((type_name.clone(), value.clone())) {
                out.entry(type_name).or_default().push(value);
            }
        }
    }
    Ok(out)
}

fn is_valid_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn write_constants(path: &Path, conditions: &BTreeMap<String, Vec<String>>) -> Result<()> {
    let mut out = String::from(
        "//! Gateway API condition `type`/`reason` constants, parsed directly from the upstream Go\n\
         //! source (`apis/v1`, `apisx/v1alpha1`) at the tag pinned in `.gateway-api-version` — see\n\
         //! the repo-root `xtask` crate. Regenerate with\n\
         //! `cargo run -p xtask -- gateway-api-types` — do not edit by hand.\n",
    );

    for (name, variants) in conditions {
        let _ = writeln!(out, "\n#[derive(Debug, Clone, Copy, PartialEq, Eq)]");
        let _ = writeln!(out, "pub enum {name} {{");
        for v in variants {
            let _ = writeln!(out, "    {v},");
        }
        out.push_str("}\n");

        let _ = writeln!(out, "\nimpl std::fmt::Display for {name} {{");
        out.push_str("    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n");
        out.push_str("        write!(f, \"{self:?}\")\n");
        out.push_str("    }\n");
        out.push_str("}\n");
    }

    fs::write(path, out).with_context(|| format!("failed to write {}", path.display()))
}

// -----------------------------------------------------------------------------
// Formatting
// -----------------------------------------------------------------------------

fn cargo_fmt(root: &Path) -> Result<()> {
    let status = Command::new("cargo")
        .args(["fmt", "-p", "gateway-api-types"])
        .current_dir(root)
        .status()
        .context("failed to run `cargo fmt -p gateway-api-types`")?;
    if !status.success() {
        bail!("cargo fmt -p gateway-api-types failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_conditions_extracts_type_and_reason_pairs() {
        let source = (
            "apis/v1/gateway_types.go".to_string(),
            r#"
const (
	GatewayConditionProgrammed GatewayConditionType = "Programmed"
	GatewayReasonProgrammed GatewayConditionReason = "Programmed"
	GatewayReasonInvalid GatewayConditionReason = "Invalid"
)
"#
            .to_string(),
        );

        let parsed =
            parse_conditions(std::slice::from_ref(&source)).expect("regex is a valid literal");

        assert_eq!(
            parsed.get("GatewayConditionType").map(Vec::as_slice),
            Some(["Programmed".to_string()].as_slice())
        );
        assert_eq!(
            parsed.get("GatewayConditionReason").map(Vec::as_slice),
            Some(["Programmed".to_string(), "Invalid".to_string()].as_slice())
        );
    }

    #[test]
    fn parse_conditions_skips_type_aliases() {
        let source = (
            "apis/v1beta1/gateway_types.go".to_string(),
            "type GatewayConditionType = v1.GatewayConditionType\n".to_string(),
        );

        let parsed =
            parse_conditions(std::slice::from_ref(&source)).expect("regex is a valid literal");

        assert!(
            parsed.is_empty(),
            "alias declarations must not produce a variant"
        );
    }

    #[test]
    fn parse_conditions_dedupes_identical_values_across_files() {
        let v1 = (
            "apis/v1/shared_types.go".to_string(),
            r#"RouteConditionAccepted RouteConditionType = "Accepted""#.to_string(),
        );
        let v1alpha2 = (
            "apis/v1alpha2/shared_types.go".to_string(),
            r#"RouteConditionAccepted RouteConditionType = "Accepted""#.to_string(),
        );

        let parsed = parse_conditions(&[v1, v1alpha2]).expect("regex is a valid literal");

        assert_eq!(parsed.get("RouteConditionType").map(Vec::len), Some(1));
    }

    #[test]
    fn append_enum_defaults_skips_doc_comments_and_attributes() {
        let generated = "\
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq)]
pub enum HttpRouteRulesFiltersType {
    /// A doc comment kopium emits per-variant.
    #[serde(rename = \"RequestHeaderModifier\")]
    RequestHeaderModifier,
    ResponseHeaderModifier,
}
";
        let out = append_enum_defaults(generated);
        assert!(out.contains("impl Default for HttpRouteRulesFiltersType"));
        assert!(out.contains("HttpRouteRulesFiltersType::RequestHeaderModifier"));
    }

    #[test]
    fn append_enum_defaults_preserves_raw_identifier_variants() {
        // kopium emits `r#_301` for numeric-looking CRD enum values (e.g. an
        // HTTP redirect status code) — the `r#` prefix must survive into the
        // generated `impl Default`, or it references a nonexistent `r` variant.
        let generated = "\
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq)]
pub enum HttpRouteRulesFiltersRequestRedirectStatusCode {
    #[serde(rename = \"301\")]
    r#_301,
    #[serde(rename = \"302\")]
    r#_302,
}
";
        let out = append_enum_defaults(generated);
        assert!(out.contains("impl Default for HttpRouteRulesFiltersRequestRedirectStatusCode"));
        assert!(out.contains("HttpRouteRulesFiltersRequestRedirectStatusCode::r#_301"));
        assert!(
            !out.contains("::r {"),
            "must not truncate the raw identifier to a bare `r`"
        );
    }

    #[test]
    fn first_enum_variant_returns_none_for_empty_enum() {
        assert_eq!(first_enum_variant(&["}"]), None);
    }

    #[test]
    fn is_valid_ident_rejects_hyphenated_values() {
        assert!(is_valid_ident("Accepted"));
        assert!(!is_valid_ident("Not-A-Rust-Ident"));
        assert!(!is_valid_ident("1Leading"));
    }
}
