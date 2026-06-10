//! Prints the `CoxswainGatewayParameters` CRD YAML to stdout.
//!
//! Run after touching `crates/coxswain-core/src/crd/gateway_parameters.rs` to
//! regenerate the committed CRD manifests:
//!
//! ```bash
//! cargo run -p coxswain-core --example crdgen \
//!     > deploy/manifests/crds/coxswaingatewayparameters.yaml
//! cp deploy/manifests/crds/coxswaingatewayparameters.yaml \
//!     charts/coxswain/crds/coxswaingatewayparameters.yaml
//! ```
//!
//! The snapshot test in `coxswain-core` fails on drift between this generator
//! and the committed YAML.

use coxswain_core::crd::CoxswainGatewayParameters;
use kube::CustomResourceExt;

fn main() -> Result<(), serde_yaml::Error> {
    serde_yaml::to_writer(std::io::stdout(), &CoxswainGatewayParameters::crd())
}
