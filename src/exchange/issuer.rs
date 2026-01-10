//! Token issuer for generating exchanged tokens.

use anyhow::{anyhow, Context, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

use super::config::TokenExchangeConfig;

/// Token issuer for creating new JWTs.
pub struct TokenIssuer {
    /// Signing key.
    encoding_key: EncodingKey,
    /// Signing algorithm.
    algorithm: Algorithm,
    /// Issuer claim.
    issuer: String,
    /// Default audience.
    default_audience: Option<String>,
    /// Default TTL.
    default_ttl_secs: u64,
}

impl TokenIssuer {
    /// Create a new token issuer from configuration.
    pub fn new(config: &TokenExchangeConfig) -> Result<Self> {
        let algorithm = parse_algorithm(&config.signing_algorithm)?;

        let key_data = if let Some(ref path) = config.signing_key_path {
            std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read signing key: {:?}", path))?
        } else if let Some(ref inline) = config.signing_key_inline {
            inline.clone()
        } else {
            return Err(anyhow!("No signing key provided"));
        };

        let encoding_key = create_encoding_key(&key_data, algorithm)?;

        let issuer = config
            .issuer
            .clone()
            .ok_or_else(|| anyhow!("Issuer must be configured"))?;

        Ok(Self {
            encoding_key,
            algorithm,
            issuer,
            default_audience: config.default_audience.clone(),
            default_ttl_secs: config.token_ttl_secs,
        })
    }

    /// Issue a new token.
    pub fn issue_token(
        &self,
        subject: &str,
        audience: Option<&str>,
        scopes: Option<&[String]>,
        extra_claims: HashMap<String, serde_json::Value>,
        ttl_secs: Option<u64>,
    ) -> Result<IssuedToken> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let ttl = ttl_secs.unwrap_or(self.default_ttl_secs);
        let exp = now + ttl;

        let aud = audience
            .map(String::from)
            .or_else(|| self.default_audience.clone());

        let scope_str = scopes.map(|s| s.join(" "));

        let claims = TokenClaims {
            iss: self.issuer.clone(),
            sub: subject.to_string(),
            aud,
            exp,
            iat: now,
            nbf: Some(now),
            jti: Some(generate_jti()),
            scope: scope_str,
            extra: extra_claims,
        };

        let header = Header::new(self.algorithm);
        let token = encode(&header, &claims, &self.encoding_key)
            .context("Failed to encode token")?;

        debug!(
            sub = %subject,
            aud = ?claims.aud,
            exp = %exp,
            "Issued new token"
        );

        Ok(IssuedToken {
            token,
            expires_in: ttl,
            token_type: "Bearer".to_string(),
            scope: claims.scope,
        })
    }
}

/// Claims for issued tokens.
#[derive(Debug, Serialize, Deserialize)]
struct TokenClaims {
    /// Issuer.
    iss: String,
    /// Subject.
    sub: String,
    /// Audience (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    /// Expiration time.
    exp: u64,
    /// Issued at.
    iat: u64,
    /// Not before (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<u64>,
    /// JWT ID (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
    /// Scopes (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    /// Extra claims.
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

/// Issued token result.
#[derive(Debug)]
pub struct IssuedToken {
    /// The JWT token.
    pub token: String,
    /// Expires in seconds.
    pub expires_in: u64,
    /// Token type (always "Bearer").
    pub token_type: String,
    /// Scopes (if any).
    pub scope: Option<String>,
}

/// Parse algorithm string to jsonwebtoken Algorithm.
fn parse_algorithm(alg: &str) -> Result<Algorithm> {
    match alg {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "HS256" => Ok(Algorithm::HS256),
        "HS384" => Ok(Algorithm::HS384),
        "HS512" => Ok(Algorithm::HS512),
        _ => Err(anyhow!("Unsupported algorithm: {}", alg)),
    }
}

/// Create encoding key from key data.
fn create_encoding_key(key_data: &str, algorithm: Algorithm) -> Result<EncodingKey> {
    let key_data = key_data.trim();

    match algorithm {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            if key_data.contains("-----BEGIN RSA PRIVATE KEY-----") {
                EncodingKey::from_rsa_pem(key_data.as_bytes())
                    .context("Failed to parse RSA private key (PKCS#1)")
            } else if key_data.contains("-----BEGIN PRIVATE KEY-----") {
                EncodingKey::from_rsa_pem(key_data.as_bytes())
                    .context("Failed to parse RSA private key (PKCS#8)")
            } else {
                Err(anyhow!("RSA key must be in PEM format"))
            }
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            if key_data.contains("-----BEGIN EC PRIVATE KEY-----")
                || key_data.contains("-----BEGIN PRIVATE KEY-----")
            {
                EncodingKey::from_ec_pem(key_data.as_bytes())
                    .context("Failed to parse EC private key")
            } else {
                Err(anyhow!("EC key must be in PEM format"))
            }
        }
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            // Symmetric key - could be base64 encoded or raw
            let key_bytes = if key_data.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
                // Looks like base64
                use base64::{engine::general_purpose::STANDARD, Engine};
                STANDARD.decode(key_data).unwrap_or_else(|_| key_data.as_bytes().to_vec())
            } else {
                key_data.as_bytes().to_vec()
            };
            Ok(EncodingKey::from_secret(&key_bytes))
        }
        _ => Err(anyhow!("Unsupported algorithm for key creation")),
    }
}

/// Generate a unique JWT ID.
fn generate_jti() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_algorithm() {
        assert!(matches!(parse_algorithm("RS256"), Ok(Algorithm::RS256)));
        assert!(matches!(parse_algorithm("ES256"), Ok(Algorithm::ES256)));
        assert!(matches!(parse_algorithm("HS256"), Ok(Algorithm::HS256)));
        assert!(parse_algorithm("INVALID").is_err());
    }

    #[test]
    fn test_symmetric_key_encoding() {
        let key = create_encoding_key("my-secret-key", Algorithm::HS256);
        assert!(key.is_ok());
    }

    #[test]
    fn test_issue_token_with_symmetric_key() {
        let config = TokenExchangeConfig {
            enabled: true,
            signing_key_inline: Some("test-secret-key-that-is-long-enough".to_string()),
            signing_algorithm: "HS256".to_string(),
            issuer: Some("https://auth.example.com".to_string()),
            default_audience: Some("api".to_string()),
            token_ttl_secs: 3600,
            ..Default::default()
        };

        let issuer = TokenIssuer::new(&config).unwrap();
        let result = issuer.issue_token(
            "user123",
            None,
            Some(&["read".to_string(), "write".to_string()]),
            HashMap::new(),
            None,
        );

        assert!(result.is_ok());
        let token = result.unwrap();
        assert!(!token.token.is_empty());
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.expires_in, 3600);
        assert_eq!(token.scope, Some("read write".to_string()));
    }
}
