//! Cross-cutting integration tests for `coxswain-discovery`.
//!
//! These tests span multiple modules and require a real TLS handshake, so they
//! live here rather than inline in individual source files.

mod scope_binding;
