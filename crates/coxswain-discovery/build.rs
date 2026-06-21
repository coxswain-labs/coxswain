//! Build script for `coxswain-discovery`.
//!
//! Compiles `proto/coxswain/discovery/v1/discovery.proto` using `protox`
//! (pure-Rust; no system `protoc` required) and feeds the resulting
//! `FileDescriptorSet` to `tonic-prost-build` to emit the Rust bindings into
//! `$OUT_DIR`.

use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // CARGO_MANIFEST_DIR is the absolute path to the crate root
    // (crates/coxswain-discovery/). Two levels up is the workspace root.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or_else(|| {
            panic!("invariant: CARGO_MANIFEST_DIR has at least two parent directories")
        });

    let proto_include = workspace_root.join("proto");
    let proto_file = proto_include.join("coxswain/discovery/v1/discovery.proto");

    let fds = protox::compile([proto_file], [proto_include])?;
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_fds(fds)?;
    Ok(())
}
