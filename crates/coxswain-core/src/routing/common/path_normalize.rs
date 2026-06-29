//! Envoy/Istio-style path normalization levels for routing and forwarding.
//!
//! Each level is a strict superset of the previous — `base` ⊂ `merge-slashes` ⊂
//! `decode-and-merge-slashes`.  `base` is the secure floor: there is no
//! identity/passthrough level, because disabling normalization re-opens
//! route-match bypass and path-traversal attacks.
//!
//! The model mirrors Istio's `MeshConfig.pathNormalization` (Envoy's
//! `normalize_path` + `merge_slashes` + `path_with_escaped_slashes_action`),
//! verified against the Istio normalization reference.
//!
//! # Security invariant
//!
//! `%2F` and `%5C` (percent-encoded slash and backslash) are **never** decoded
//! at the `base` or `merge-slashes` levels.  Decoding them would introduce new
//! segment boundaries after slash-merging, enabling path-traversal bypasses.
//! Only `decode-and-merge-slashes` deliberately decodes them — operators who
//! select that level accept the associated risk.

use std::borrow::Cow;

/// Path normalization level applied before routing lookup and retained as the
/// forwarded upstream path.
///
/// Defaults to [`NormalizeLevel::Base`], which decodes unreserved
/// percent-encoded characters, converts backslashes to forward slashes, and
/// applies RFC 3986 §5.2.4 dot-segment removal — matching Istio's mesh-wide
/// baseline.  Operators may only *widen* the level per Ingress via the
/// `ingress.coxswain-labs.dev/path-normalize` annotation; there is no
/// passthrough/identity level, so normalization can never be disabled (a
/// disabled level re-opens route-match bypass / path-traversal attacks).
/// Gateway API routes always use the default (`Base`) — the shared
/// `HostRouter` default materialises this without any annotation.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NormalizeLevel {
    /// Percent-decode unreserved characters (RFC 3986 §2.3), convert `\` to
    /// `/`, and apply RFC 3986 §5.2.4 dot-segment removal.  Does **not** merge
    /// consecutive slashes.  Equivalent to Istio `BASE`.  This is the default
    /// for all routes (Ingress and Gateway API) and the secure floor.
    #[default]
    Base,
    /// All of `Base`, plus collapse runs of `/` into a single `/`.  Equivalent
    /// to Istio `MERGE_SLASHES`.
    MergeSlashes,
    /// All of `MergeSlashes`, plus decode `%2F`→`/` and `%5C`→`\` before
    /// slash-merging.  Equivalent to Istio `DECODE_AND_MERGE_SLASHES`.
    DecodeAndMergeSlashes,
}

impl NormalizeLevel {
    /// Normalize `path` according to this level, returning the result as a
    /// [`Cow`].
    ///
    /// Returns [`Cow::Borrowed`] when the path is already canonical — the
    /// common clean-path case costs one linear scan and zero allocation.
    /// Returns [`Cow::Owned`] only when normalization actually changed the path
    /// (one `String` allocation, then one `Arc::from` at the call site).
    pub(crate) fn apply(self, path: &str) -> Cow<'_, str> {
        if !needs_slow_path(path, self) {
            return Cow::Borrowed(path);
        }
        let normalized = run_normalization(path, self);
        if normalized == path {
            Cow::Borrowed(path)
        } else {
            Cow::Owned(normalized)
        }
    }
}

// ─── Fast pre-scan ───────────────────────────────────────────────────────────

/// Returns `true` when `path` contains bytes that signal normalization is
/// needed at `level`.
///
/// Checks for:
/// - `%` — a percent-encoded sequence (may need decoding)
/// - `\` — backslash (converted to `/`)
/// - `/.` — potential dot segment (`.` or `..`)
/// - `//` — consecutive slashes (only relevant for merge+ levels)
///
/// A `false` return means `Cow::Borrowed` is safe — the overwhelmingly common
/// clean-path case costs one linear scan and zero allocation.
fn needs_slow_path(path: &str, level: NormalizeLevel) -> bool {
    let bytes = path.as_bytes();
    let check_double_slash = matches!(
        level,
        NormalizeLevel::MergeSlashes | NormalizeLevel::DecodeAndMergeSlashes
    );
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' | b'\\' => return true,
            b'/' if i + 1 < bytes.len() => {
                let next = bytes[i + 1];
                if next == b'.' || (check_double_slash && next == b'/') {
                    return true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

// ─── Level-gated normalization pipeline ──────────────────────────────────────

fn run_normalization(path: &str, level: NormalizeLevel) -> String {
    // Step 1: decode escaped slashes (`%2F` → `/`, `%5C` → `\`).
    // Only at `decode-and-merge-slashes`; decoded `\` is re-normalised by step
    // 3 and decoded `/` is collapsed by step 5.
    let s: String = if level == NormalizeLevel::DecodeAndMergeSlashes {
        decode_escaped_slashes(path)
    } else {
        path.to_owned()
    };

    // Step 2: percent-decode unreserved characters (RFC 3986 §2.3).
    // `%2F` and `%5C` are intentionally excluded here (see module-level
    // security invariant).  `%2E` → `.` is decoded so that `/../` via
    // `%2E%2E` is caught by step 4.
    let s = decode_unreserved(&s);

    // Step 3: convert `\` to `/`.
    let s: String = if s.contains('\\') {
        s.replace('\\', "/")
    } else {
        s
    };

    // Step 4: RFC 3986 §5.2.4 dot-segment removal (`.` / `..`).
    let s = remove_dot_segments(&s);

    // Step 5: collapse consecutive `/` → single `/` (merge+ levels only).
    if matches!(
        level,
        NormalizeLevel::MergeSlashes | NormalizeLevel::DecodeAndMergeSlashes
    ) {
        merge_slashes(&s)
    } else {
        s
    }
}

// ─── Normalization primitives ─────────────────────────────────────────────────

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

fn is_unreserved(b: u8) -> bool {
    // RFC 3986 §2.3: ALPHA / DIGIT / "-" / "." / "_" / "~"
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Decode `%2F` → `/` and `%5C` → `\` (case-insensitive hex).
///
/// Used only at the `decode-and-merge-slashes` level before slash-merging.
fn decode_escaped_slashes(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let decoded = (hex_val(bytes[i + 1]) << 4) | hex_val(bytes[i + 2]);
            if matches!(decoded, b'/' | b'\\') {
                out.push(char::from(decoded));
                i += 3;
                continue;
            }
        }
        // Copy the next character verbatim, respecting multi-byte UTF-8 boundaries.
        let ch = s[i..].chars().next().unwrap_or_else(|| {
            panic!("invariant: i < bytes.len() guarantees a char at byte offset {i}")
        });
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Percent-decode unreserved characters (RFC 3986 §2.3).
///
/// Never decodes `%2F`/`%5C` — those are handled by `decode_escaped_slashes`
/// at the appropriate level.  Decoding `%2E` (`.`) here ensures that
/// percent-encoded dot segments (e.g. `%2E%2E`) are caught by
/// `remove_dot_segments`.
fn decode_unreserved(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let decoded = (hex_val(bytes[i + 1]) << 4) | hex_val(bytes[i + 2]);
            if is_unreserved(decoded) {
                // decoded is always an ASCII byte; char::from is safe for any u8.
                out.push(char::from(decoded));
                i += 3;
                continue;
            }
        }
        // Copy the next character verbatim, respecting multi-byte UTF-8 boundaries.
        let ch = s[i..].chars().next().unwrap_or_else(|| {
            panic!("invariant: i < bytes.len() guarantees a char at byte offset {i}")
        });
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// RFC 3986 §5.2.4 dot-segment removal for absolute paths.
///
/// `.` segments are dropped; `..` segments pop the last output segment.
/// Consecutive slashes are preserved — they are handled separately by
/// `merge_slashes`.  Never pops past the root: `/../` at the root returns `/`.
fn remove_dot_segments(path: &str) -> String {
    // Output is never longer than input.
    let mut out = String::with_capacity(path.len());
    let mut input = path;

    while !input.is_empty() {
        // A. Strip leading `../` or `./` (anomalous in absolute paths; handled
        //    for robustness per the RFC).
        if let Some(rest) = input.strip_prefix("../") {
            input = rest;
            continue;
        }
        if let Some(rest) = input.strip_prefix("./") {
            input = rest;
            continue;
        }
        // B. Replace leading `/./` with `/`, or trailing `/.` with `/`.
        if input.starts_with("/./") {
            input = &input[2..]; // keep the `/`, consume the `.`
            continue;
        }
        if input == "/." {
            input = "/";
            continue;
        }
        // C. Replace leading `/../` with `/` and pop the last output segment,
        //    or handle the trailing `/..` form.
        if input.starts_with("/../") {
            input = &input[3..]; // keep the `/`, consume `..`
            pop_last_segment(&mut out);
            continue;
        }
        if input == "/.." {
            input = "/";
            pop_last_segment(&mut out);
            continue;
        }
        // D. Lone `.` or `..` — consume and stop (nothing to emit).
        if input == "." || input == ".." {
            break;
        }
        // E. Move the first path segment (including its leading `/`) to output.
        let end = if let Some(rest) = input.strip_prefix('/') {
            // Find the next `/` after the opening `/`.
            rest.find('/').map(|p| p + 1).unwrap_or(input.len())
        } else {
            input.find('/').unwrap_or(input.len())
        };
        out.push_str(&input[..end]);
        input = &input[end..];
    }

    if out.is_empty() { "/".to_owned() } else { out }
}

/// Remove the last path segment (everything after and including the last `/`)
/// from `out`.  Never pops past an empty buffer — at the root, the next
/// iteration's `input` will start with `/` which reconstructs it.
fn pop_last_segment(out: &mut String) {
    if let Some(pos) = out.rfind('/') {
        out.truncate(pos);
    }
}

/// Collapse runs of `/` into a single `/`.
fn merge_slashes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_slash = false;
    for ch in s.chars() {
        if ch == '/' {
            if !prev_slash {
                out.push('/');
            }
            prev_slash = true;
        } else {
            out.push(ch);
            prev_slash = false;
        }
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn base(path: &str) -> Cow<'_, str> {
        NormalizeLevel::Base.apply(path)
    }
    fn merge(path: &str) -> Cow<'_, str> {
        NormalizeLevel::MergeSlashes.apply(path)
    }
    fn decode_merge(path: &str) -> Cow<'_, str> {
        NormalizeLevel::DecodeAndMergeSlashes.apply(path)
    }

    // ── Base: dot-segment removal ─────────────────────────────────────────────

    #[test]
    fn base_dot_dot_resolves() {
        assert_eq!(base("/api/../v1").as_ref(), "/v1");
    }

    #[test]
    fn base_single_dot_removed() {
        assert_eq!(base("/foo/./bar").as_ref(), "/foo/bar");
    }

    #[test]
    fn base_trailing_dot_dot_returns_root() {
        assert_eq!(base("/foo/..").as_ref(), "/");
    }

    #[test]
    fn base_double_dot_at_root_stays_root() {
        assert_eq!(base("/../").as_ref(), "/");
    }

    #[test]
    fn base_deep_traversal_resolved() {
        assert_eq!(base("/a/b/c/../../d").as_ref(), "/a/d");
    }

    // ── Base: encoded dots ────────────────────────────────────────────────────

    #[test]
    fn base_encoded_dot_decoded_then_removed() {
        // %2E → `.` after decode_unreserved, then dot-segment removal applies.
        assert_eq!(base("/foo/%2e%2e/bar").as_ref(), "/bar");
        assert_eq!(base("/foo/%2E%2E/bar").as_ref(), "/bar");
    }

    #[test]
    fn base_encoded_single_dot_removed() {
        assert_eq!(base("/foo/%2e/bar").as_ref(), "/foo/bar");
    }

    // ── Base: backslash ───────────────────────────────────────────────────────

    #[test]
    fn base_backslash_converted_to_slash() {
        assert_eq!(base("/foo\\bar").as_ref(), "/foo/bar");
    }

    // ── Base: percent-encoded unreserved chars ────────────────────────────────

    #[test]
    fn base_encoded_tilde_decoded() {
        assert_eq!(base("/foo%7Ebar").as_ref(), "/foo~bar");
    }

    #[test]
    fn base_encoded_hyphen_decoded() {
        assert_eq!(base("/foo%2Dbar").as_ref(), "/foo-bar");
    }

    // ── Base: %2F is NOT decoded ──────────────────────────────────────────────

    #[test]
    fn base_encoded_slash_not_decoded() {
        // %2F must remain encoded at base level — decoding it would introduce
        // a new segment boundary and defeat the traversal guard.
        let path = "/api%2Fv1";
        let result = base(path);
        assert_eq!(result.as_ref(), "/api%2Fv1");
    }

    #[test]
    fn base_encoded_backslash_not_decoded() {
        let path = "/api%5Cv1";
        assert_eq!(base(path).as_ref(), "/api%5Cv1");
    }

    // ── Base: double-slash NOT merged ─────────────────────────────────────────

    #[test]
    fn base_double_slash_not_merged() {
        // Base does not merge slashes — that is the `merge-slashes` level.
        assert_eq!(base("//api//v1").as_ref(), "//api//v1");
    }

    // ── Base: clean paths cost one scan, no allocation ────────────────────────

    #[test]
    fn base_clean_path_is_borrowed() {
        let path = "/api/v1";
        assert!(matches!(base(path), Cow::Borrowed(p) if p == path));
    }

    #[test]
    fn base_root_is_borrowed() {
        let path = "/";
        assert!(matches!(base(path), Cow::Borrowed(p) if p == path));
    }

    #[test]
    fn base_dot_in_filename_no_change() {
        // `/foo/.bar` triggers the pre-scan (contains `/.`) but the
        // segment `.bar` is not a dot-segment — result equals input.
        let path = "/foo/.bar";
        assert!(matches!(base(path), Cow::Borrowed(p) if p == path));
    }

    // ── MergeSlashes ──────────────────────────────────────────────────────────

    #[test]
    fn merge_slashes_collapses_doubles() {
        assert_eq!(merge("//api//v1").as_ref(), "/api/v1");
    }

    #[test]
    fn merge_slashes_plus_dot_segment() {
        assert_eq!(merge("//api/../v1").as_ref(), "/v1");
    }

    #[test]
    fn merge_slashes_clean_path_is_borrowed() {
        let path = "/api/v1";
        assert!(matches!(merge(path), Cow::Borrowed(p) if p == path));
    }

    // ── DecodeAndMergeSlashes ────────────────────────────────────────────────

    #[test]
    fn decode_and_merge_encoded_slash_decoded_and_merged() {
        // %2F → `/`, then `//api` is merged to `/api`.
        assert_eq!(decode_merge("/api%2Fv1").as_ref(), "/api/v1");
    }

    #[test]
    fn decode_and_merge_encoded_backslash_becomes_slash() {
        assert_eq!(decode_merge("/api%5Cv1").as_ref(), "/api/v1");
    }

    #[test]
    fn decode_and_merge_full_chain() {
        // Encoded backslash → `/`, then double slashes merged, then dot removed.
        assert_eq!(decode_merge("//api%5C..//v1").as_ref(), "/v1");
    }

    // ── Idempotency ───────────────────────────────────────────────────────────

    #[test]
    fn base_idempotent() {
        let path = "/api/../v1";
        let first = NormalizeLevel::Base.apply(path);
        let second = NormalizeLevel::Base.apply(first.as_ref());
        assert_eq!(first.as_ref(), second.as_ref());
    }

    #[test]
    fn merge_slashes_idempotent() {
        let path = "//api//v1";
        let first = NormalizeLevel::MergeSlashes.apply(path);
        let second = NormalizeLevel::MergeSlashes.apply(first.as_ref());
        assert_eq!(first.as_ref(), second.as_ref());
    }
}
