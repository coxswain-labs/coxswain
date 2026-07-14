//! Prints a Coxswain CRD YAML to stdout.
//!
//! Pass the CRD kind as the first argument. With no argument, defaults to
//! `GatewayParameters` for backward compatibility.
//!
//! ## Regenerate manifests after touching a CRD type
//!
//! ```bash
//! # ClientTrafficPolicy
//! cargo run -p coxswain-core --example crdgen -- ClientTrafficPolicy \
//!     > deploy/manifests/crds/clienttrafficpolicies.yaml
//! cp deploy/manifests/crds/clienttrafficpolicies.yaml \
//!     charts/coxswain/crds/clienttrafficpolicies.yaml
//!
//! # CoxswainBackendPolicy
//! cargo run -p coxswain-core --example crdgen -- CoxswainBackendPolicy \
//!     > deploy/manifests/crds/coxswainbackendpolicies.yaml
//! cp deploy/manifests/crds/coxswainbackendpolicies.yaml \
//!     charts/coxswain/crds/coxswainbackendpolicies.yaml
//!
//! # CoxswainExternalAuth
//! cargo run -p coxswain-core --example crdgen -- CoxswainExternalAuth \
//!     > deploy/manifests/crds/coxswainexternalauths.yaml
//! cp deploy/manifests/crds/coxswainexternalauths.yaml \
//!     charts/coxswain/crds/coxswainexternalauths.yaml
//!
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
//! # CoxswainRelayPolicy
//! cargo run -p coxswain-core --example crdgen -- CoxswainRelayPolicy \
//!     > deploy/manifests/crds/coxswainrelaypolicies.yaml
//! cp deploy/manifests/crds/coxswainrelaypolicies.yaml \
//!     charts/coxswain/crds/coxswainrelaypolicies.yaml
//!
//! # RateLimit
//! cargo run -p coxswain-core --example crdgen -- RateLimit \
//!     > deploy/manifests/crds/ratelimits.yaml
//! cp deploy/manifests/crds/ratelimits.yaml \
//!     charts/coxswain/crds/ratelimits.yaml
//!
//! # IpAccessControl
//! cargo run -p coxswain-core --example crdgen -- IpAccessControl \
//!     > deploy/manifests/crds/ipaccesscontrols.yaml
//! cp deploy/manifests/crds/ipaccesscontrols.yaml \
//!     charts/coxswain/crds/ipaccesscontrols.yaml
//!
//! # BasicAuth
//! cargo run -p coxswain-core --example crdgen -- BasicAuth \
//!     > deploy/manifests/crds/basicauths.yaml
//! cp deploy/manifests/crds/basicauths.yaml \
//!     charts/coxswain/crds/basicauths.yaml
//!
//! # RequestSizeLimit
//! cargo run -p coxswain-core --example crdgen -- RequestSizeLimit \
//!     > deploy/manifests/crds/requestsizelimits.yaml
//! cp deploy/manifests/crds/requestsizelimits.yaml \
//!     charts/coxswain/crds/requestsizelimits.yaml
//!
//! # Compression
//! cargo run -p coxswain-core --example crdgen -- Compression \
//!     > deploy/manifests/crds/compressions.yaml
//! cp deploy/manifests/crds/compressions.yaml \
//!     charts/coxswain/crds/compressions.yaml
//!
//! # RetryPolicy
//! cargo run -p coxswain-core --example crdgen -- RetryPolicy \
//!     > deploy/manifests/crds/retrypolicies.yaml
//! cp deploy/manifests/crds/retrypolicies.yaml \
//!     charts/coxswain/crds/retrypolicies.yaml
//!
//! # JwtAuth
//! cargo run -p coxswain-core --example crdgen -- JwtAuth \
//!     > deploy/manifests/crds/jwtauths.yaml
//! cp deploy/manifests/crds/jwtauths.yaml \
//!     charts/coxswain/crds/jwtauths.yaml
//! ```
//!
//! The snapshot tests in `coxswain-core` fail on drift between this generator
//! and the committed YAML.

use coxswain_core::crd::{
    BasicAuth, ClientTrafficPolicy, Compression, CoxswainBackendPolicy, CoxswainExternalAuth,
    CoxswainGatewayParameters, CoxswainIngressClassParameters, CoxswainRelayPolicy,
    IpAccessControl, JwtAuth, PathRewriteRegex, RateLimit, RequestSizeLimit, RetryPolicy,
};
use kube::CustomResourceExt;

fn main() -> Result<(), serde_yaml::Error> {
    let kind = std::env::args().nth(1).unwrap_or_default();
    match kind.as_str() {
        "ClientTrafficPolicy" => {
            serde_yaml::to_writer(std::io::stdout(), &ClientTrafficPolicy::crd())
        }
        "CoxswainBackendPolicy" => {
            serde_yaml::to_writer(std::io::stdout(), &CoxswainBackendPolicy::crd())
        }
        "CoxswainExternalAuth" => {
            serde_yaml::to_writer(std::io::stdout(), &CoxswainExternalAuth::crd())
        }
        "IngressClassParameters" => {
            serde_yaml::to_writer(std::io::stdout(), &CoxswainIngressClassParameters::crd())
        }
        "CoxswainRelayPolicy" => {
            serde_yaml::to_writer(std::io::stdout(), &CoxswainRelayPolicy::crd())
        }
        "RateLimit" => serde_yaml::to_writer(std::io::stdout(), &RateLimit::crd()),
        "PathRewriteRegex" => serde_yaml::to_writer(std::io::stdout(), &PathRewriteRegex::crd()),
        "IpAccessControl" => serde_yaml::to_writer(std::io::stdout(), &IpAccessControl::crd()),
        "BasicAuth" => serde_yaml::to_writer(std::io::stdout(), &BasicAuth::crd()),
        "RequestSizeLimit" => serde_yaml::to_writer(std::io::stdout(), &RequestSizeLimit::crd()),
        "Compression" => serde_yaml::to_writer(std::io::stdout(), &Compression::crd()),
        "RetryPolicy" => serde_yaml::to_writer(std::io::stdout(), &RetryPolicy::crd()),
        "JwtAuth" => serde_yaml::to_writer(std::io::stdout(), &JwtAuth::crd()),
        // No arg or "GatewayParameters" → gateway (backward-compatible default).
        _ => serde_yaml::to_writer(std::io::stdout(), &CoxswainGatewayParameters::crd()),
    }
}
