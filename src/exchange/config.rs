//! Token Exchange configuration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Token Exchange configuration (RFC 8693).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenExchangeConfig {
    /// Enable token exchange endpoint.
    #[serde(default)]
    pub enabled: bool,

    /// Endpoint path for token exchange.
    #[serde(default = "default_endpoint")]
    pub endpoint_path: String,

    /// Path to signing key (PEM format) for issued tokens.
    #[serde(default)]
    pub signing_key_path: Option<PathBuf>,

    /// Inline signing key (base64-encoded for symmetric, PEM for asymmetric).
    #[serde(default)]
    pub signing_key_inline: Option<String>,

    /// Signing algorithm (RS256, ES256, HS256).
    #[serde(default = "default_algorithm")]
    pub signing_algorithm: String,

    /// Issuer claim for issued tokens.
    #[serde(default)]
    pub issuer: Option<String>,

    /// Default audience for issued tokens.
    #[serde(default)]
    pub default_audience: Option<String>,

    /// Token TTL in seconds.
    #[serde(default = "default_ttl")]
    pub token_ttl_secs: u64,

    /// Allowed exchange rules.
    #[serde(default)]
    pub allowed_exchanges: Vec<ExchangeRule>,

    /// Log exchange operations.
    #[serde(default)]
    pub log_exchanges: bool,
}

fn default_endpoint() -> String {
    "/token/exchange".to_string()
}

fn default_algorithm() -> String {
    "RS256".to_string()
}

fn default_ttl() -> u64 {
    3600 // 1 hour
}

impl Default for TokenExchangeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint_path: default_endpoint(),
            signing_key_path: None,
            signing_key_inline: None,
            signing_algorithm: default_algorithm(),
            issuer: None,
            default_audience: None,
            token_ttl_secs: default_ttl(),
            allowed_exchanges: vec![],
            log_exchanges: false,
        }
    }
}

impl TokenExchangeConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        // Must have a signing key
        if self.signing_key_path.is_none() && self.signing_key_inline.is_none() {
            return Err("Token exchange requires signing_key_path or signing_key_inline".to_string());
        }

        // If key path specified, check it exists
        if let Some(ref path) = self.signing_key_path {
            if !path.exists() {
                return Err(format!("Signing key file does not exist: {:?}", path));
            }
        }

        // Validate algorithm
        let valid_algs = ["RS256", "RS384", "RS512", "ES256", "ES384", "HS256", "HS384", "HS512"];
        if !valid_algs.contains(&self.signing_algorithm.as_str()) {
            return Err(format!(
                "Invalid signing algorithm: {}. Valid: {:?}",
                self.signing_algorithm, valid_algs
            ));
        }

        // Must have an issuer
        if self.issuer.is_none() {
            return Err("Token exchange requires issuer to be configured".to_string());
        }

        Ok(())
    }

    /// Check if an exchange is allowed.
    pub fn is_exchange_allowed(&self, from: &TokenType, to: &TokenType) -> bool {
        if self.allowed_exchanges.is_empty() {
            return true; // No restrictions
        }
        self.allowed_exchanges
            .iter()
            .any(|rule| &rule.subject_token_type == from && &rule.issued_token_type == to)
    }

    /// Get scope mapping for an exchange.
    pub fn get_scope_mapping(&self, from: &TokenType, to: &TokenType) -> Option<&HashMap<String, Vec<String>>> {
        self.allowed_exchanges
            .iter()
            .find(|rule| &rule.subject_token_type == from && &rule.issued_token_type == to)
            .map(|rule| &rule.scope_mapping)
    }
}

/// Token type URNs (RFC 8693).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// OAuth 2.0 access token.
    AccessToken,
    /// OpenID Connect ID token.
    IdToken,
    /// SAML 2.0 assertion.
    Saml2,
    /// Generic JWT.
    Jwt,
    /// Refresh token.
    RefreshToken,
}

impl TokenType {
    /// Get the URN for this token type.
    pub fn as_urn(&self) -> &'static str {
        match self {
            TokenType::AccessToken => "urn:ietf:params:oauth:token-type:access_token",
            TokenType::IdToken => "urn:ietf:params:oauth:token-type:id_token",
            TokenType::Saml2 => "urn:ietf:params:oauth:token-type:saml2",
            TokenType::Jwt => "urn:ietf:params:oauth:token-type:jwt",
            TokenType::RefreshToken => "urn:ietf:params:oauth:token-type:refresh_token",
        }
    }

    /// Parse from URN string.
    pub fn from_urn(urn: &str) -> Option<Self> {
        match urn {
            "urn:ietf:params:oauth:token-type:access_token" => Some(TokenType::AccessToken),
            "urn:ietf:params:oauth:token-type:id_token" => Some(TokenType::IdToken),
            "urn:ietf:params:oauth:token-type:saml2" => Some(TokenType::Saml2),
            "urn:ietf:params:oauth:token-type:jwt" => Some(TokenType::Jwt),
            "urn:ietf:params:oauth:token-type:refresh_token" => Some(TokenType::RefreshToken),
            _ => None,
        }
    }
}

/// Exchange rule defining allowed token conversions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeRule {
    /// Token type being exchanged (input).
    pub subject_token_type: TokenType,
    /// Token type to issue (output).
    pub issued_token_type: TokenType,
    /// Scope mapping: input scope -> output scopes.
    #[serde(default)]
    pub scope_mapping: HashMap<String, Vec<String>>,
}

/// JSON configuration for dynamic reconfiguration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct TokenExchangeConfigJson {
    pub enabled: Option<bool>,
    pub endpoint_path: Option<String>,
    pub signing_key_path: Option<String>,
    pub signing_key_inline: Option<String>,
    pub signing_algorithm: Option<String>,
    pub issuer: Option<String>,
    pub default_audience: Option<String>,
    pub token_ttl_secs: Option<u64>,
    pub log_exchanges: Option<bool>,
}

impl TokenExchangeConfigJson {
    /// Apply JSON config to existing config.
    pub fn apply_to(&self, config: &mut TokenExchangeConfig) {
        if let Some(enabled) = self.enabled {
            config.enabled = enabled;
        }
        if let Some(ref path) = self.endpoint_path {
            config.endpoint_path = path.clone();
        }
        if let Some(ref path) = self.signing_key_path {
            config.signing_key_path = Some(PathBuf::from(path));
        }
        if let Some(ref key) = self.signing_key_inline {
            config.signing_key_inline = Some(key.clone());
        }
        if let Some(ref alg) = self.signing_algorithm {
            config.signing_algorithm = alg.clone();
        }
        if let Some(ref iss) = self.issuer {
            config.issuer = Some(iss.clone());
        }
        if let Some(ref aud) = self.default_audience {
            config.default_audience = Some(aud.clone());
        }
        if let Some(ttl) = self.token_ttl_secs {
            config.token_ttl_secs = ttl;
        }
        if let Some(log) = self.log_exchanges {
            config.log_exchanges = log;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_type_urn_roundtrip() {
        let types = [
            TokenType::AccessToken,
            TokenType::IdToken,
            TokenType::Saml2,
            TokenType::Jwt,
            TokenType::RefreshToken,
        ];

        for t in types {
            let urn = t.as_urn();
            let parsed = TokenType::from_urn(urn).unwrap();
            assert_eq!(t, parsed);
        }
    }

    #[test]
    fn test_exchange_allowed() {
        let mut config = TokenExchangeConfig::default();

        // No rules = allow all
        assert!(config.is_exchange_allowed(&TokenType::Saml2, &TokenType::AccessToken));

        // With rules
        config.allowed_exchanges = vec![ExchangeRule {
            subject_token_type: TokenType::Saml2,
            issued_token_type: TokenType::AccessToken,
            scope_mapping: HashMap::new(),
        }];

        assert!(config.is_exchange_allowed(&TokenType::Saml2, &TokenType::AccessToken));
        assert!(!config.is_exchange_allowed(&TokenType::Jwt, &TokenType::AccessToken));
    }

    #[test]
    fn test_default_config() {
        let config = TokenExchangeConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.endpoint_path, "/token/exchange");
        assert_eq!(config.signing_algorithm, "RS256");
        assert_eq!(config.token_ttl_secs, 3600);
    }
}
