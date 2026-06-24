//! Prints a Coxswain CRD YAML to stdout.
//!
//! Pass the CRD kind as the first argument. With no argument, defaults to
//! `GatewayParameters` for backward compatibility.
//!
//! ## Regenerate manifests after touching a CRD type
//!
//! ```bash
//! # CoxswainGatewayParameters
//! cargo run -p coxswain-core --example crdgen \
//!     > deploy/manifests/crds/coxswaingatewayparameters.yaml
//! cp deploy/manifests/crds/coxswaingatewayparameters.yaml \
//!     charts/coxswain/crds/coxswaingatewayparameters.yaml
//!
//! # CoxswainIngressClassParameters
//! cargo run -p coxswain-core --example crdgen -- IngressClassParameters \
//!     > deploy/manifests/crds/coxswainingressclassparameters.yaml
//! cp deploy/manifests/crds/coxswainingressclassparameters.yaml \
//!     charts/coxswain/crds/coxswainingressclassparameters.yaml
//!
//! # RateLimit
//! cargo run -p coxswain-core --example crdgen -- RateLimit \
//!     > deploy/manifests/crds/ratelimits.yaml
//! cp deploy/manifests/crds/ratelimits.yaml \
//!     charts/coxswain/crds/ratelimits.yaml
//! ```
//!
//! The snapshot tests in `coxswain-core` fail on drift between this generator
//! and the committed YAML.

use coxswain_core::crd::{
    CoxswainGatewayParameters, CoxswainIngressClassParameters, PathRewriteRegex, RateLimit,
};
use kube::CustomResourceExt;

fn main() -> Result<(), serde_yaml::Error> {
    let kind = std::env::args().nth(1).unwrap_or_default();
    match kind.as_str() {
        "IngressClassParameters" => {
            serde_yaml::to_writer(std::io::stdout(), &CoxswainIngressClassParameters::crd())
        }
        "RateLimit" => serde_yaml::to_writer(std::io::stdout(), &RateLimit::crd()),
        "PathRewriteRegex" => serde_yaml::to_writer(std::io::stdout(), &PathRewriteRegex::crd()),
        // No arg or "GatewayParameters" → gateway (backward-compatible default).
        _ => serde_yaml::to_writer(std::io::stdout(), &CoxswainGatewayParameters::crd()),
    }
}
