//! OIDC configuration.

use jsonwebtoken::Algorithm;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// OIDC/OAuth 2.0 configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Enable OIDC authentication.
    #[serde(default)]
    pub enabled: bool,

    /// Token issuer (iss claim). Must match exactly.
    /// Example: "https://auth.example.com"
    #[serde(default)]
    pub issuer: String,

    /// JWKS endpoint URL for fetching public keys.
    /// Example: "https://auth.example.com/.well-known/jwks.json"
    #[serde(default)]
    pub jwks_url: String,

    /// Expected audience (aud claim). Optional.
    #[serde(default)]
    pub audience: Option<String>,

    /// Required OAuth scopes. Request must have all listed scopes.
    #[serde(default)]
    pub required_scopes: Vec<String>,

    /// JWKS cache refresh interval in seconds.
    #[serde(default = "default_jwks_refresh")]
    pub jwks_refresh_secs: u64,

    /// Clock skew tolerance in seconds for exp/nbf validation.
    #[serde(default = "default_clock_skew")]
    pub clock_skew_secs: i64,

    /// Claim to use as user ID. Defaults to "sub".
    #[serde(default = "default_user_claim")]
    pub user_id_claim: String,

    /// Claim containing scopes. Defaults to "scope".
    #[serde(default = "default_scope_claim")]
    pub scope_claim: String,

    /// Signature algorithms a token may use. Empty means the asymmetric
    /// algorithms the JWKS keys declare (`RS256`, `ES256` or `ES384` for a
    /// key that declares none). `none` and the symmetric `HS*` algorithms
    /// are always refused.
    #[serde(default)]
    pub allowed_algorithms: Vec<String>,

    /// Minimum seconds between two JWKS fetches. A token with an unknown
    /// `kid` triggers at most one refetch per interval; unknown key IDs are
    /// remembered as unknown until the next fetch.
    #[serde(default = "default_jwks_min_refetch")]
    pub jwks_min_refetch_secs: u64,

    /// Timeout for one JWKS fetch, in milliseconds.
    #[serde(default = "default_jwks_fetch_timeout")]
    pub jwks_fetch_timeout_ms: u64,
}

/// Longest JWKS fetch timeout accepted, in milliseconds.
pub const MAX_JWKS_FETCH_TIMEOUT_MS: u64 = 30_000;

/// Parse a JWS algorithm name that may verify a token against a JWKS public
/// key.
///
/// `none` is refused, and so are the `HS*` algorithms: with a public key as
/// the HMAC secret, anyone holding the public key could sign tokens
/// (algorithm confusion). Only the algorithms the JWKS loader can build keys
/// for are accepted.
pub fn parse_asymmetric_algorithm(name: &str) -> Result<Algorithm, String> {
    match name.trim().to_ascii_uppercase().as_str() {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "NONE" => Err("algorithm `none` (unsigned tokens) is never accepted".to_string()),
        "HS256" | "HS384" | "HS512" => Err(format!(
            "symmetric algorithm `{name}` cannot verify tokens against JWKS public keys \
             (algorithm confusion); use RS*, PS* or ES*"
        )),
        _ => Err(format!("unsupported OIDC signature algorithm `{name}`")),
    }
}

fn default_jwks_refresh() -> u64 {
    3600 // 1 hour
}

fn default_clock_skew() -> i64 {
    30 // 30 seconds
}

fn default_user_claim() -> String {
    "sub".to_string()
}

fn default_scope_claim() -> String {
    "scope".to_string()
}

fn default_jwks_min_refetch() -> u64 {
    60
}

fn default_jwks_fetch_timeout() -> u64 {
    5_000
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: String::new(),
            jwks_url: String::new(),
            audience: None,
            required_scopes: Vec::new(),
            jwks_refresh_secs: default_jwks_refresh(),
            clock_skew_secs: default_clock_skew(),
            user_id_claim: default_user_claim(),
            scope_claim: default_scope_claim(),
            allowed_algorithms: Vec::new(),
            jwks_min_refetch_secs: default_jwks_min_refetch(),
            jwks_fetch_timeout_ms: default_jwks_fetch_timeout(),
        }
    }
}

impl OidcConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        // Checked even when disabled: a list naming `none` or HS* is never
        // what anyone wants, and enabling later must not be the first check.
        self.explicit_allowed_algorithms()?;

        if !self.enabled {
            return Ok(());
        }

        if self.jwks_min_refetch_secs == 0 {
            return Err("OIDC jwks-min-refetch-secs must be at least 1".to_string());
        }

        if self.jwks_fetch_timeout_ms == 0 || self.jwks_fetch_timeout_ms > MAX_JWKS_FETCH_TIMEOUT_MS
        {
            return Err(format!(
                "OIDC jwks-fetch-timeout-ms must be between 1 and {MAX_JWKS_FETCH_TIMEOUT_MS}"
            ));
        }

        if self.issuer.is_empty() {
            return Err("OIDC issuer is required".to_string());
        }

        if self.jwks_url.is_empty() {
            return Err("OIDC jwks_url is required".to_string());
        }

        // Validate URL format
        if !self.jwks_url.starts_with("https://") && !self.jwks_url.starts_with("http://") {
            return Err("OIDC jwks_url must be a valid HTTP(S) URL".to_string());
        }

        Ok(())
    }

    /// The configured `allowed-algorithms`, parsed. `None` when the list is
    /// empty, meaning "whatever the JWKS keys declare".
    pub fn explicit_allowed_algorithms(&self) -> Result<Option<HashSet<Algorithm>>, String> {
        if self.allowed_algorithms.is_empty() {
            return Ok(None);
        }
        self.allowed_algorithms
            .iter()
            .map(|name| {
                parse_asymmetric_algorithm(name)
                    .map_err(|e| format!("OIDC allowed-algorithms: {e}"))
            })
            .collect::<Result<HashSet<_>, _>>()
            .map(Some)
    }
}

/// JSON configuration for dynamic reconfiguration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OidcConfigJson {
    pub enabled: Option<bool>,
    pub issuer: Option<String>,
    pub jwks_url: Option<String>,
    pub audience: Option<String>,
    #[serde(default)]
    pub required_scopes: Vec<String>,
    pub jwks_refresh_secs: Option<u64>,
    pub clock_skew_secs: Option<i64>,
    pub user_id_claim: Option<String>,
    pub scope_claim: Option<String>,
    #[serde(default)]
    pub allowed_algorithms: Vec<String>,
    pub jwks_min_refetch_secs: Option<u64>,
    pub jwks_fetch_timeout_ms: Option<u64>,
}

impl OidcConfigJson {
    /// Apply JSON config to existing config.
    pub fn apply_to(&self, config: &mut OidcConfig) {
        if let Some(enabled) = self.enabled {
            config.enabled = enabled;
        }
        if let Some(ref issuer) = self.issuer {
            config.issuer = issuer.clone();
        }
        if let Some(ref jwks_url) = self.jwks_url {
            config.jwks_url = jwks_url.clone();
        }
        if let Some(ref audience) = self.audience {
            config.audience = Some(audience.clone());
        }
        if !self.required_scopes.is_empty() {
            config.required_scopes = self.required_scopes.clone();
        }
        if let Some(refresh) = self.jwks_refresh_secs {
            config.jwks_refresh_secs = refresh;
        }
        if let Some(skew) = self.clock_skew_secs {
            config.clock_skew_secs = skew;
        }
        if let Some(ref claim) = self.user_id_claim {
            config.user_id_claim = claim.clone();
        }
        if let Some(ref claim) = self.scope_claim {
            config.scope_claim = claim.clone();
        }
        if !self.allowed_algorithms.is_empty() {
            config.allowed_algorithms = self.allowed_algorithms.clone();
        }
        if let Some(secs) = self.jwks_min_refetch_secs {
            config.jwks_min_refetch_secs = secs;
        }
        if let Some(ms) = self.jwks_fetch_timeout_ms {
            config.jwks_fetch_timeout_ms = ms;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = OidcConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.jwks_refresh_secs, 3600);
        assert_eq!(config.clock_skew_secs, 30);
        assert_eq!(config.user_id_claim, "sub");
    }

    #[test]
    fn test_validation() {
        let mut config = OidcConfig::default();
        assert!(config.validate().is_ok()); // disabled is valid

        config.enabled = true;
        assert!(config.validate().is_err()); // missing issuer

        config.issuer = "https://auth.example.com".to_string();
        assert!(config.validate().is_err()); // missing jwks_url

        config.jwks_url = "https://auth.example.com/.well-known/jwks.json".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_json_apply() {
        let mut config = OidcConfig::default();
        let json = OidcConfigJson {
            enabled: Some(true),
            issuer: Some("https://auth.example.com".to_string()),
            jwks_url: Some("https://auth.example.com/.well-known/jwks.json".to_string()),
            audience: Some("my-api".to_string()),
            required_scopes: vec!["read".to_string(), "write".to_string()],
            jwks_refresh_secs: Some(1800),
            clock_skew_secs: None,
            user_id_claim: None,
            scope_claim: None,
            ..Default::default()
        };

        json.apply_to(&mut config);

        assert!(config.enabled);
        assert_eq!(config.issuer, "https://auth.example.com");
        assert_eq!(config.audience, Some("my-api".to_string()));
        assert_eq!(config.required_scopes, vec!["read", "write"]);
        assert_eq!(config.jwks_refresh_secs, 1800);
        assert_eq!(config.clock_skew_secs, 30); // unchanged
    }

    #[test]
    fn allowed_algorithms_refuse_none_and_symmetric() {
        for bad in ["none", "None", "HS256", "hs384", "HS512"] {
            let config = OidcConfig {
                allowed_algorithms: vec!["RS256".to_string(), bad.to_string()],
                ..Default::default()
            };
            let err = config.validate().unwrap_err();
            assert!(err.contains("allowed-algorithms"), "{bad}: {err}");
        }

        let config = OidcConfig {
            allowed_algorithms: vec!["RS256".to_string(), "es256".to_string()],
            ..Default::default()
        };
        let algs = config.explicit_allowed_algorithms().unwrap().unwrap();
        assert!(algs.contains(&Algorithm::RS256) && algs.contains(&Algorithm::ES256));
        assert!(OidcConfig::default()
            .explicit_allowed_algorithms()
            .unwrap()
            .is_none());
    }

    #[test]
    fn refetch_and_timeout_bounds_are_validated() {
        let base = OidcConfig {
            enabled: true,
            issuer: "https://auth.example.com".to_string(),
            jwks_url: "https://auth.example.com/jwks".to_string(),
            ..Default::default()
        };
        assert!(base.validate().is_ok());
        let zero_refetch = OidcConfig {
            jwks_min_refetch_secs: 0,
            ..base.clone()
        };
        assert!(zero_refetch.validate().is_err());
        let long_timeout = OidcConfig {
            jwks_fetch_timeout_ms: MAX_JWKS_FETCH_TIMEOUT_MS + 1,
            ..base
        };
        assert!(long_timeout.validate().is_err());
    }
}
