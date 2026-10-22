//! Static API keys and Basic auth users.
//!
//! API keys are kept only as SHA-256 digests and looked up by comparing the
//! presented key's digest with every configured one in constant time, so the
//! lookup takes the same time whichever key (if any) matches.
//!
//! Basic auth passwords are bcrypt hashes (`$2a$`, `$2b$`, `$2y$`, e.g. from
//! `htpasswd -nbB`). Plain-text passwords are accepted only with an explicit
//! opt-in, and are then compared in constant time as well.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::warn;

use crate::secret::{digests_equal, secret_digest, SecretDigest};

/// A configured API key.
#[derive(Debug, Clone)]
pub struct ApiKeyInfo {
    /// SHA-256 of the key; the key itself is not kept.
    pub key_digest: SecretDigest,
    /// Name, used as the user ID.
    pub name: String,
}

/// Parse `key:name` entries.
pub fn parse_api_keys<'a>(entries: impl IntoIterator<Item = &'a str>) -> Vec<ApiKeyInfo> {
    entries
        .into_iter()
        .filter_map(|pair| pair.trim().split_once(':'))
        .map(|(key, name)| ApiKeyInfo {
            key_digest: secret_digest(key.trim().as_bytes()),
            name: name.trim().to_string(),
        })
        .collect()
}

/// Find the API key matching `presented`, comparing against every key in
/// constant time without stopping at a match.
pub fn find_api_key<'a>(keys: &'a [ApiKeyInfo], presented: &str) -> Option<&'a ApiKeyInfo> {
    let digest = secret_digest(presented.as_bytes());
    let mut found = None;
    for key in keys {
        if digests_equal(&key.key_digest, &digest) {
            found = Some(key);
        }
    }
    found
}

/// How a Basic auth password is checked.
#[derive(Debug, Clone)]
pub enum PasswordCheck {
    /// A bcrypt hash.
    Bcrypt(String),
    /// A plain-text password (opt-in only), kept as its SHA-256 digest.
    Plaintext(SecretDigest),
}

/// A Basic auth user.
#[derive(Debug, Clone)]
pub struct BasicAuthUser {
    pub username: String,
    pub password: PasswordCheck,
    /// Digest of the last password that passed bcrypt, so a returning
    /// client does not pay for bcrypt (100+ ms) on every request. Only a
    /// correct password can get here.
    verified: Arc<RwLock<Option<SecretDigest>>>,
}

impl BasicAuthUser {
    pub fn new(username: String, password: PasswordCheck) -> Self {
        Self {
            username,
            password,
            verified: Arc::new(RwLock::new(None)),
        }
    }

    /// Check a password without bcrypt, if possible: `Some(result)` for a
    /// plain-text password or a cached bcrypt success, `None` when bcrypt
    /// has to run.
    pub fn quick_check(&self, password: &str) -> Option<bool> {
        let digest = secret_digest(password.as_bytes());
        match &self.password {
            PasswordCheck::Plaintext(expected) => Some(digests_equal(expected, &digest)),
            PasswordCheck::Bcrypt(_) => {
                let cached = self.verified.read().ok().and_then(|g| *g);
                match cached {
                    Some(ok) if digests_equal(&ok, &digest) => Some(true),
                    _ => None,
                }
            }
        }
    }

    /// Run bcrypt (blocking; call from a blocking thread) and remember a
    /// success.
    pub fn bcrypt_check(&self, password: &str) -> bool {
        let PasswordCheck::Bcrypt(ref hash) = self.password else {
            return false;
        };
        let ok = bcrypt::verify(password, hash).unwrap_or(false);
        if ok {
            if let Ok(mut cached) = self.verified.write() {
                *cached = Some(secret_digest(password.as_bytes()));
            }
        }
        ok
    }
}

/// A bcrypt hash checked for unknown users, so an unknown user takes as
/// long as a wrong password. (cost 12, password "x")
pub const DUMMY_BCRYPT_HASH: &str = "$2y$12$fee.cA6Py7ZPStdEHiuldOA.or8reLV2lcer1Gv5uLfUw83p8z0si";

/// Run bcrypt against [`DUMMY_BCRYPT_HASH`] (blocking).
pub fn dummy_bcrypt_check(password: &str) {
    let _ = bcrypt::verify(password, DUMMY_BCRYPT_HASH);
}

fn is_bcrypt_hash(s: &str) -> bool {
    ["$2a$", "$2b$", "$2x$", "$2y$"]
        .iter()
        .any(|p| s.starts_with(p))
}

/// Parse `user:password` entries. The password must be a bcrypt hash unless
/// `allow_plaintext` is set.
pub fn parse_basic_auth_users<'a>(
    entries: impl IntoIterator<Item = &'a str>,
    allow_plaintext: bool,
) -> Result<HashMap<String, BasicAuthUser>> {
    let mut users = HashMap::new();
    let mut plaintext = Vec::new();
    for entry in entries {
        let entry = entry.trim();
        let Some((user, pass)) = entry.split_once(':') else {
            continue;
        };
        let (user, pass) = (user.trim(), pass.trim());
        let check = if is_bcrypt_hash(pass) {
            pass.parse::<bcrypt::HashParts>()
                .map_err(|e| anyhow!("Basic auth user '{user}': invalid bcrypt hash: {e}"))?;
            PasswordCheck::Bcrypt(pass.to_string())
        } else if allow_plaintext {
            plaintext.push(user.to_string());
            PasswordCheck::Plaintext(secret_digest(pass.as_bytes()))
        } else {
            return Err(anyhow!(
                "Basic auth user '{user}': the password is not a bcrypt hash. Use a bcrypt \
                 hash (e.g. `htpasswd -nbB {user} <password>`), or set \
                 basic-auth-allow-plaintext (--basic-auth-allow-plaintext) to accept \
                 plain-text passwords"
            ));
        };
        users.insert(
            user.to_string(),
            BasicAuthUser::new(user.to_string(), check),
        );
    }
    if !plaintext.is_empty() {
        warn!(
            users = ?plaintext,
            "Basic auth users with plain-text passwords (basic-auth-allow-plaintext); \
             use bcrypt hashes instead"
        );
    }
    Ok(users)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated with `htpasswd -nbB -C 4 alice s3cret`.
    pub(crate) const ALICE_BCRYPT: &str =
        "$2y$04$fqtNxPl7APYvfBv0y4Wt5.VI.B4ylGv6lyMXZlI6QCa/JVLPn6zAq";

    #[test]
    fn api_keys_are_found_by_digest() {
        let keys = parse_api_keys(["k1:one", " k2 : two ", "malformed"]);
        assert_eq!(keys.len(), 2);
        assert_eq!(find_api_key(&keys, "k2").unwrap().name, "two");
        assert!(find_api_key(&keys, "k3").is_none());
        assert!(find_api_key(&keys, "k").is_none());
        assert!(find_api_key(&keys, "").is_none());
    }

    #[test]
    fn plaintext_passwords_need_the_opt_in() {
        let err = parse_basic_auth_users(["alice:s3cret"], false).unwrap_err();
        assert!(
            err.to_string().contains("basic-auth-allow-plaintext"),
            "{err}"
        );

        let users = parse_basic_auth_users(["alice:s3cret"], true).unwrap();
        let alice = &users["alice"];
        assert_eq!(alice.quick_check("s3cret"), Some(true));
        assert_eq!(alice.quick_check("s3cre"), Some(false));
    }

    #[test]
    fn bcrypt_hashes_verify_and_cache_success() {
        let entry = format!("alice:{ALICE_BCRYPT}");
        let users = parse_basic_auth_users([entry.as_str()], false).unwrap();
        let alice = &users["alice"];
        assert_eq!(alice.quick_check("s3cret"), None);
        assert!(!alice.bcrypt_check("wrong"));
        assert_eq!(alice.quick_check("wrong"), None);
        assert!(alice.bcrypt_check("s3cret"));
        assert_eq!(alice.quick_check("s3cret"), Some(true));
        // A wrong password after a success still needs bcrypt.
        assert_eq!(alice.quick_check("s3cret2"), None);
    }

    #[test]
    fn a_malformed_bcrypt_hash_is_rejected() {
        assert!(parse_basic_auth_users(["alice:$2b$12$tooshort"], false).is_err());
    }

    #[test]
    fn the_dummy_hash_is_a_valid_bcrypt_hash() {
        assert!(DUMMY_BCRYPT_HASH.parse::<bcrypt::HashParts>().is_ok());
        assert!(bcrypt::verify("x", DUMMY_BCRYPT_HASH).unwrap());
    }
}
