#![allow(missing_docs)]
//! Security data-plane: edge access control. **Placeholder — no tests yet.**
//!
//! Plane: **data-plane**. Execution: **parallel** — partition-local edge policy.
//!
//! Classification rule: a test belongs to the plane of its *primary assertion
//! target*. This file is the home for the v0.3 edge-security feature effect
//! tests as they land: IP allow/deny source-range (#264), client-cert mTLS
//! (#267), `satisfy` any/all (#268), external authorization (#273), and
//! per-client rate limiting (#24/#25). Upstream TLS verification
//! (`BackendTLSPolicy`, mTLS to the backend) lives in `tls.rs`.
