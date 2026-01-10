//! OIDC token validation.

use anyhow::{anyhow, Context, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;

use super::config::OidcConfig;
use super::jwks::JwksCache;

/// Standard OIDC/JWT claims.
#[derive(Debug, Serialize, Deserialize)]
pub struct OidcClaims {
    /// Subject (user identifier)
    pub sub: Option<String>,
    /// Issuer
    pub iss: Option<String>,
    /// Audience (can be string or array)
    #[serde(default)]
    pub aud: Audience,
    /// Expiration time
    pub exp: Option<u64>,
    /// Not before
    pub nbf: Option<u64>,
    /// Issued at
    pub iat: Option<u64>,
    /// JWT ID
    pub jti: Option<String>,
    /// Scopes (space-separated string)
    pub scope: Option<String>,
    /// Email
    pub email: Option<String>,
    /// Email verified
    pub email_verified: Option<bool>,
    /// Name
    pub name: Option<String>,
    /// Preferred username
    pub preferred_username: Option<String>,
    /// Additional claims
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Audience can be a single string or array of strings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    #[default]
    None,
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    pub fn contains(&self, aud: &str) -> bool {
        match self {
            Audience::None => false,
            Audience::Single(s) => s == aud,
            Audience::Multiple(v) => v.iter().any(|a| a == aud),
        }
    }
}

/// Validated identity from OIDC token.
#[derive(Debug)]
pub struct OidcIdentity {
    /// User ID (from configured claim)
    pub user_id: String,
    /// Token scopes
    pub scopes: Vec<String>,
    /// All claims as key-value pairs
    pub claims: HashMap<String, String>,
}

/// Validate an OIDC/OAuth2 token.
pub async fn validate_oidc_token(
    config: &OidcConfig,
    jwks: &JwksCache,
    token: &str,
) -> Result<OidcIdentity> {
    // Decode header to get kid and algorithm
    let header = decode_header(token).context("Failed to decode token header")?;

    debug!(
        kid = ?header.kid,
        alg = ?header.alg,
        "Validating OIDC token"
    );

    // Get the decoding key
    let decoding_key = if let Some(ref kid) = header.kid {
        jwks.get_key(kid).await?
    } else {
        // No kid specified, use default key
        jwks.get_default_key().await?
    };

    // Build validation
    let mut validation = Validation::new(header.alg);
    validation.leeway = config.clock_skew_secs as u64;

    // Set issuer validation
    validation.set_issuer(&[&config.issuer]);

    // Set audience validation if configured
    if let Some(ref aud) = config.audience {
        validation.set_audience(&[aud]);
    } else {
        validation.validate_aud = false;
    }

    // Validate required claims
    validation.set_required_spec_claims(&["exp", "iss"]);

    // Decode and validate
    let token_data = decode::<OidcClaims>(token, &decoding_key, &validation)
        .context("Token validation failed")?;

    let claims = token_data.claims;

    // Extract user ID from configured claim
    let user_id = extract_claim_value(&claims, &config.user_id_claim)
        .ok_or_else(|| anyhow!("User ID claim '{}' not found in token", config.user_id_claim))?;

    // Extract scopes
    let scopes = extract_scopes(&claims, &config.scope_claim);

    // Check required scopes
    for required in &config.required_scopes {
        if !scopes.contains(required) {
            return Err(anyhow!("Missing required scope: {}", required));
        }
    }

    // Build claims map for headers
    let claims_map = build_claims_map(&claims);

    debug!(
        user_id = %user_id,
        scopes = ?scopes,
        "OIDC token validated"
    );

    Ok(OidcIdentity {
        user_id,
        scopes,
        claims: claims_map,
    })
}

/// Extract a claim value as string.
fn extract_claim_value(claims: &OidcClaims, claim_name: &str) -> Option<String> {
    match claim_name {
        "sub" => claims.sub.clone(),
        "email" => claims.email.clone(),
        "name" => claims.name.clone(),
        "preferred_username" => claims.preferred_username.clone(),
        _ => claims
            .extra
            .get(claim_name)
            .and_then(|v| match v {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Number(n) => Some(n.to_string()),
                _ => None,
            }),
    }
}

/// Extract scopes from token.
fn extract_scopes(claims: &OidcClaims, scope_claim: &str) -> Vec<String> {
    // Try the configured scope claim
    let scope_str = if scope_claim == "scope" {
        claims.scope.clone()
    } else {
        claims.extra.get(scope_claim).and_then(|v| match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Array(arr) => {
                let strs: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                Some(strs.join(" "))
            }
            _ => None,
        })
    };

    scope_str
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default()
}

/// Build a flat map of claims for headers.
fn build_claims_map(claims: &OidcClaims) -> HashMap<String, String> {
    let mut map = HashMap::new();

    if let Some(ref sub) = claims.sub {
        map.insert("sub".to_string(), sub.clone());
    }
    if let Some(ref iss) = claims.iss {
        map.insert("iss".to_string(), iss.clone());
    }
    if let Some(ref email) = claims.email {
        map.insert("email".to_string(), email.clone());
    }
    if let Some(ref name) = claims.name {
        map.insert("name".to_string(), name.clone());
    }
    if let Some(ref username) = claims.preferred_username {
        map.insert("preferred_username".to_string(), username.clone());
    }
    if let Some(ref scope) = claims.scope {
        map.insert("scope".to_string(), scope.clone());
    }
    if let Some(exp) = claims.exp {
        map.insert("exp".to_string(), exp.to_string());
    }
    if let Some(iat) = claims.iat {
        map.insert("iat".to_string(), iat.to_string());
    }

    // Add extra claims (flatten simple values only)
    for (key, value) in &claims.extra {
        match value {
            serde_json::Value::String(s) => {
                map.insert(key.clone(), s.clone());
            }
            serde_json::Value::Number(n) => {
                map.insert(key.clone(), n.to_string());
            }
            serde_json::Value::Bool(b) => {
                map.insert(key.clone(), b.to_string());
            }
            _ => {} // Skip complex values
        }
    }

    map
}

/// Get the algorithm from token header for validation.
pub fn get_token_algorithm(token: &str) -> Result<Algorithm> {
    let header = decode_header(token).context("Failed to decode token header")?;
    Ok(header.alg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audience_contains() {
        let single = Audience::Single("api".to_string());
        assert!(single.contains("api"));
        assert!(!single.contains("other"));

        let multi = Audience::Multiple(vec!["api".to_string(), "web".to_string()]);
        assert!(multi.contains("api"));
        assert!(multi.contains("web"));
        assert!(!multi.contains("other"));

        let none = Audience::None;
        assert!(!none.contains("anything"));
    }

    #[test]
    fn test_scope_extraction() {
        let mut claims = OidcClaims {
            sub: Some("user123".to_string()),
            iss: Some("https://auth.example.com".to_string()),
            aud: Audience::None,
            exp: Some(9999999999),
            nbf: None,
            iat: None,
            jti: None,
            scope: Some("read write admin".to_string()),
            email: None,
            email_verified: None,
            name: None,
            preferred_username: None,
            extra: HashMap::new(),
        };

        let scopes = extract_scopes(&claims, "scope");
        assert_eq!(scopes, vec!["read", "write", "admin"]);

        // Test with array in extra claims
        claims.extra.insert(
            "permissions".to_string(),
            serde_json::json!(["read", "write"]),
        );
        let scopes = extract_scopes(&claims, "permissions");
        assert_eq!(scopes, vec!["read", "write"]);
    }
}
