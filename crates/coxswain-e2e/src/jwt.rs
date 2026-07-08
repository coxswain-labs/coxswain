//! Test-JWT minting for the `JwtAuth` e2e scenarios (#441).
//!
//! The matching **public** JWKS (one ES256 key, `kid = "e2e-test-key"`) is
//! embedded inline in `fixtures/gateway_api/jwt_auth_extensionref.yaml` and
//! `fixtures/ingress/annotation_auth_jwt.yaml` — both fixtures resolve to the
//! same `JwtAuth` spec, so one signing helper covers both surfaces. The
//! private half lives only here, never in a fixture.
//!
//! [`TEST_ISSUER`] must match both fixtures' `spec.issuer`.

use std::time::{SystemTime, UNIX_EPOCH};

/// Expected `iss` claim, matching both `JwtAuth` fixtures' `spec.issuer`.
pub const TEST_ISSUER: &str = "https://issuer.e2e.coxswain-labs.dev";

/// `kid` of the embedded test key, matching both fixtures' inline JWKS.
const TEST_KID: &str = "e2e-test-key";

/// Static P-256 PKCS8 DER test private key. Generated once via `openssl
/// ecparam -genkey -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -outform
/// DER`; its public half is embedded as the inline JWKS in both `JwtAuth`
/// fixtures. Test-only — never used to sign anything outside this crate.
const TEST_EC_PRIVATE_KEY_DER: &[u8] = &[
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
    0x01, 0x01, 0x04, 0x20, 0x4c, 0x79, 0x89, 0x2d, 0x11, 0xbc, 0xc1, 0x22, 0x36, 0x4f, 0x07, 0xb2,
    0xee, 0x30, 0xa7, 0x21, 0x0d, 0x11, 0x88, 0x90, 0xf7, 0x36, 0xc4, 0xe6, 0xd1, 0xc3, 0x57, 0xc7,
    0x25, 0x12, 0x2d, 0x40, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x49, 0xc3, 0xae, 0x03, 0x38, 0x71,
    0x05, 0xb0, 0xc8, 0x1b, 0x35, 0xf0, 0x1e, 0x50, 0x1c, 0x9f, 0x49, 0xc7, 0xb7, 0xcb, 0x44, 0xf4,
    0xeb, 0xea, 0x44, 0x79, 0xb7, 0x44, 0x81, 0x90, 0x8e, 0x4f, 0x26, 0x23, 0x1e, 0xe0, 0xa5, 0xd6,
    0x68, 0x18, 0x16, 0x20, 0x10, 0xf5, 0x4d, 0x39, 0x30, 0x41, 0xd2, 0x4d, 0x6c, 0xb9, 0x0e, 0xe4,
    0x01, 0x22, 0x45, 0x04, 0x9d, 0xbf, 0xc7, 0x5b, 0x43, 0x28,
];

/// Sign a test token with claims `{iss, exp, sub, [aud]}`, tagged with
/// [`TEST_KID`] so the proxy's `kid`-narrowing lookup is exercised.
///
/// `exp_offset_secs` is added to the current Unix time — negative mints an
/// already-expired token for the sad-path tests. `audience: None` omits the
/// `aud` claim entirely (exercises the "no audience configured" path).
#[must_use]
pub fn sign_test_token(issuer: &str, audience: Option<&str>, exp_offset_secs: i64) -> String {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
        + exp_offset_secs;
    let mut claims = serde_json::json!({ "iss": issuer, "exp": exp, "sub": "e2e-test-user" });
    if let Some(aud) = audience {
        claims["aud"] = serde_json::Value::from(aud);
    }

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(TEST_KID.to_string());
    let encoding_key = jsonwebtoken::EncodingKey::from_ec_der(TEST_EC_PRIVATE_KEY_DER);
    jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap_or_else(|e| {
        panic!("invariant: signing a test JWT with a valid static key must succeed: {e}")
    })
}

/// A token that verifies cleanly against both `JwtAuth` fixtures: correct
/// issuer, no audience claim, expires one hour from now.
#[must_use]
pub fn valid_token() -> String {
    sign_test_token(TEST_ISSUER, None, 3600)
}

/// A token signed by the right key but with the wrong `iss` — must be
/// rejected (`401`).
#[must_use]
pub fn wrong_issuer_token() -> String {
    sign_test_token("https://not-the-configured-issuer.example.com", None, 3600)
}

/// A token signed by the right key, correct issuer, but already expired —
/// must be rejected (`401`).
#[must_use]
pub fn expired_token() -> String {
    sign_test_token(TEST_ISSUER, None, -3600)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The public JWKS embedded in both `JwtAuth` fixtures, verbatim from
    /// `fixtures/gateway_api/jwt_auth_extensionref.yaml`. A sanity check that
    /// [`TEST_EC_PRIVATE_KEY_DER`] actually matches — a hand-transcribed DER
    /// byte array is exactly the kind of thing that silently drifts.
    const FIXTURE_JWKS_JSON: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"e2e-test-key","alg":"ES256","x":"ScOuAzhxBbDIGzXwHlAcn0nHt8tE9OvqRHm3RIGQjk8","y":"JiMe4KXWaBgWIBD1TTkwQdJNbLkO5AEiRQSdv8dbQyg"}]}"#;

    #[test]
    fn valid_token_verifies_against_the_embedded_fixture_jwks() {
        let set: jsonwebtoken::jwk::JwkSet =
            serde_json::from_str(FIXTURE_JWKS_JSON).expect("fixture JWKS parses");
        let jwk = set
            .find(TEST_KID)
            .expect("fixture JWKS carries the test kid");
        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk).expect("fixture JWK decodes");

        let token = valid_token();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&[TEST_ISSUER]);
        validation.validate_aud = false;
        let data = jsonwebtoken::decode::<serde_json::Value>(&token, &decoding_key, &validation)
            .expect("token signed by TEST_EC_PRIVATE_KEY_DER must verify against the fixture JWKS");
        assert_eq!(data.claims["sub"], "e2e-test-user");
    }

    #[test]
    fn wrong_issuer_token_fails_issuer_check() {
        let set: jsonwebtoken::jwk::JwkSet =
            serde_json::from_str(FIXTURE_JWKS_JSON).expect("fixture JWKS parses");
        let jwk = set
            .find(TEST_KID)
            .expect("fixture JWKS carries the test kid");
        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk).expect("fixture JWK decodes");

        let token = wrong_issuer_token();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&[TEST_ISSUER]);
        validation.validate_aud = false;
        assert!(
            jsonwebtoken::decode::<serde_json::Value>(&token, &decoding_key, &validation).is_err()
        );
    }

    #[test]
    fn expired_token_fails_exp_check() {
        let set: jsonwebtoken::jwk::JwkSet =
            serde_json::from_str(FIXTURE_JWKS_JSON).expect("fixture JWKS parses");
        let jwk = set
            .find(TEST_KID)
            .expect("fixture JWKS carries the test kid");
        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk).expect("fixture JWK decodes");

        let token = expired_token();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&[TEST_ISSUER]);
        validation.validate_aud = false;
        assert!(
            jsonwebtoken::decode::<serde_json::Value>(&token, &decoding_key, &validation).is_err()
        );
    }
}
