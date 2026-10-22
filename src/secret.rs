//! Constant-time comparison of secrets.
//!
//! Both sides are hashed with SHA-256 first, so the comparison takes the same
//! time whatever the inputs' lengths and contents, and only fixed-size digests
//! are compared (with `subtle`).

use ring::digest::{digest, SHA256};
use subtle::ConstantTimeEq;

/// SHA-256 digest of a secret.
pub type SecretDigest = [u8; 32];

/// Hash a secret for later constant-time comparison.
pub fn secret_digest(secret: &[u8]) -> SecretDigest {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, secret).as_ref());
    out
}

/// Compare two digests in constant time.
pub fn digests_equal(a: &SecretDigest, b: &SecretDigest) -> bool {
    a.ct_eq(b).into()
}

/// Compare two secrets in constant time.
pub fn secrets_equal(a: &[u8], b: &[u8]) -> bool {
    digests_equal(&secret_digest(a), &secret_digest(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_and_unequal_secrets() {
        assert!(secrets_equal(b"token", b"token"));
        assert!(!secrets_equal(b"token", b"tokem"));
        assert!(!secrets_equal(b"token", b"token-longer"));
        assert!(!secrets_equal(b"", b"token"));
    }
}
