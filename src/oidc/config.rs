//! OIDC configuration.

use serde::{Deserialize, Serialize};

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
        }
    }
}

impl OidcConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
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
        };

        json.apply_to(&mut config);

        assert!(config.enabled);
        assert_eq!(config.issuer, "https://auth.example.com");
        assert_eq!(config.audience, Some("my-api".to_string()));
        assert_eq!(config.required_scopes, vec!["read", "write"]);
        assert_eq!(config.jwks_refresh_secs, 1800);
        assert_eq!(config.clock_skew_secs, 30); // unchanged
    }
}
