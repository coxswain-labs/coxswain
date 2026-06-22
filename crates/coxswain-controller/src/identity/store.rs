//! `CaStore` — load or generate the CA Secret via the Kubernetes API.
//!
//! On startup the leader reads the configured CA Secret:
//!
//! - **Present**: load into [`CertAuthority`] and return.
//! - **Absent + `mode=auto`**: the leader generates a fresh CA, persists it to
//!   the Secret (server-side apply, conflict-tolerant), and loads the winner.
//! - **Absent + `mode=external`**: return an error (fail closed — the operator
//!   must supply the Secret before deploying).
//!
//! Followers poll until the Secret appears (the leader will have written it).
//!
//! [`CertAuthority`]: super::ca::CertAuthority

// Stubbed for commit 3; full implementation in commit 5 (CA-secret watch +
// trust-bundle ConfigMap publisher).
