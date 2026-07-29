//! The rebuild epoch's tagged fold — the whole-table invalidation signal the
//! partitioned Gateway rebuild (#511) uses for inputs a per-route static scan
//! can't attribute.
//!
//! This is its own module purely to seal [`GlobalEpoch`]'s inner accumulator.
//! Rust field privacy is per-module, so a wrapper declared next to its only
//! caller still lets that caller reach through it (`epoch.0.add_hash(..)`) and
//! contribute an *untagged* term — reintroducing the collision the tag exists
//! to prevent (#692). From here the field is genuinely unreachable, so naming a
//! [`GlobalEpochInput`] variant is a compile-time obligation rather than a
//! convention a future input could quietly skip.

/// One term folded into the global epoch — names *which* input a fingerprint
/// came from, so the fold can tell two equal fingerprints apart.
///
/// Two structurally different stores can legitimately produce the exact same
/// fingerprint at the same moment — e.g. a TLS-typed Secret that also carries
/// the `auth-basic` label is one member of both the reflector's `secrets` and
/// `auth_secrets` stores, so `store_epoch` of each hashes the identical
/// `(ns, name, change_token)` — and a single `ReferenceGrant` naming both an
/// HTTPRoute and a Gateway target flattens to the same key in two different
/// `GrantSet<K>`s (the key carries no kind). Folding such a pair with no
/// per-term tag makes its presence indistinguishable from its absence: XOR
/// cancels it outright, and even a bare sum hides a *swap*, where one term
/// loses a fingerprint and another gains the same one. That is how a revoked
/// `ReferenceGrant` went on being honoured — the epoch never moved, so no
/// `(port, host)` partition was ever marked dirty (#692).
#[derive(Hash)]
pub(super) enum GlobalEpochInput {
    BackendTlsPolicies,
    CoxswainBackendPolicies,
    ExternalAuths,
    AuthSecrets,
    Secrets,
    ConfigMaps,
    ClientTrafficPolicies,
    Gateways,
    JwksGeneration,
    HttpBackendGrants,
    BasicAuthSecretGrants,
    GrpcBackendGrants,
    ExternalAuthBackendGrants,
    CertGrants,
    ExternalAuthEndpoints,
}

/// The global epoch under construction — a [`GlobalEpochInput`]-keyed fold that
/// exposes no untagged way to contribute.
///
/// See the module header for why this wrapper is the enforcement rather than
/// documentation: [`Self::add`] is the only reachable entry point, so a new
/// epoch input cannot be folded at all until it appears in
/// [`GlobalEpochInput`].
pub(super) struct GlobalEpoch(crate::fingerprint::FingerprintAccumulator);

impl GlobalEpoch {
    pub(super) fn new() -> Self {
        Self(crate::fingerprint::FingerprintAccumulator::default())
    }

    /// Fold `fingerprint` in under `input`'s tag.
    pub(super) fn add(&mut self, input: GlobalEpochInput, fingerprint: u64) {
        self.0.add_tagged(&input, fingerprint);
    }

    pub(super) fn finish(&self) -> u64 {
        self.0.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The #692 collision at the level the epoch actually folds: two *different*
    /// inputs carrying an identical fingerprint (one `ReferenceGrant` flattening
    /// the same key into two `GrantSet`s; one Secret living in two stores) must
    /// not cancel to the all-zero-fingerprint value. Under the pre-fix XOR fold
    /// these two states were byte-identical.
    #[test]
    fn equal_fingerprints_on_two_inputs_do_not_cancel() {
        let mut absent = GlobalEpoch::new();
        absent.add(GlobalEpochInput::BasicAuthSecretGrants, 0);
        absent.add(GlobalEpochInput::CertGrants, 0);

        let mut present = GlobalEpoch::new();
        present.add(GlobalEpochInput::BasicAuthSecretGrants, 0xDEAD_BEEF);
        present.add(GlobalEpochInput::CertGrants, 0xDEAD_BEEF);

        assert_ne!(
            absent.finish(),
            present.finish(),
            "a grant flattening one identical key into two grant sets must move the epoch"
        );
    }

    /// A fingerprint moving *between* two inputs is a real change (e.g. one
    /// ReferenceGrant edited from `from.kind: BasicAuth` to `from.kind: Gateway`
    /// in a single apply, revoking one access and granting another). A tag-less
    /// sum reads both states identically.
    #[test]
    fn moving_a_fingerprint_between_inputs_moves_the_epoch() {
        let mut on_basic_auth = GlobalEpoch::new();
        on_basic_auth.add(GlobalEpochInput::BasicAuthSecretGrants, 0xABCD);
        on_basic_auth.add(GlobalEpochInput::CertGrants, 0);

        let mut on_cert = GlobalEpoch::new();
        on_cert.add(GlobalEpochInput::BasicAuthSecretGrants, 0);
        on_cert.add(GlobalEpochInput::CertGrants, 0xABCD);

        assert_ne!(
            on_basic_auth.finish(),
            on_cert.finish(),
            "the same fingerprint carried by a different input must move the epoch"
        );
    }

    /// Order independence: the fold runs over stores whose iteration order is
    /// not guaranteed, so it must not depend on the sequence of `add` calls.
    #[test]
    fn fold_is_order_independent() {
        let mut forward = GlobalEpoch::new();
        forward.add(GlobalEpochInput::Secrets, 1);
        forward.add(GlobalEpochInput::AuthSecrets, 2);

        let mut reverse = GlobalEpoch::new();
        reverse.add(GlobalEpochInput::AuthSecrets, 2);
        reverse.add(GlobalEpochInput::Secrets, 1);

        assert_eq!(
            forward.finish(),
            reverse.finish(),
            "the epoch must not depend on the order terms are folded in"
        );
    }
}
