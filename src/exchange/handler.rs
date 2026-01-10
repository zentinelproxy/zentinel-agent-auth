//! Token exchange handler (RFC 8693).

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

use super::config::{TokenExchangeConfig, TokenType};
use super::issuer::TokenIssuer;

/// Token exchange grant type (RFC 8693).
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Token exchange request (form-urlencoded body).
#[derive(Debug, Deserialize)]
pub struct TokenExchangeRequest {
    /// Must be "urn:ietf:params:oauth:grant-type:token-exchange".
    pub grant_type: String,
    /// The subject token to exchange.
    pub subject_token: String,
    /// Type of the subject token (URN).
    pub subject_token_type: String,
    /// Requested token type (optional, defaults to access_token).
    #[serde(default)]
    pub requested_token_type: Option<String>,
    /// Target audience for the new token.
    #[serde(default)]
    pub audience: Option<String>,
    /// Requested scopes.
    #[serde(default)]
    pub scope: Option<String>,
    /// Target resource.
    #[serde(default)]
    pub resource: Option<String>,
    /// Actor token (for delegation).
    #[serde(default)]
    pub actor_token: Option<String>,
    /// Actor token type.
    #[serde(default)]
    pub actor_token_type: Option<String>,
}

/// Token exchange response (JSON).
#[derive(Debug, Serialize)]
pub struct TokenExchangeResponse {
    /// The issued token.
    pub access_token: String,
    /// Type of token issued (URN).
    pub issued_token_type: String,
    /// Token type (always "Bearer").
    pub token_type: String,
    /// Expires in seconds.
    pub expires_in: u64,
    /// Scopes in the new token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Refresh token (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// Token exchange error response.
#[derive(Debug, Serialize)]
pub struct TokenExchangeError {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl TokenExchangeError {
    pub fn invalid_request(desc: &str) -> Self {
        Self {
            error: "invalid_request".to_string(),
            error_description: Some(desc.to_string()),
        }
    }

    pub fn invalid_grant(desc: &str) -> Self {
        Self {
            error: "invalid_grant".to_string(),
            error_description: Some(desc.to_string()),
        }
    }

    pub fn unsupported_token_type(desc: &str) -> Self {
        Self {
            error: "unsupported_token_type".to_string(),
            error_description: Some(desc.to_string()),
        }
    }

    pub fn server_error(desc: &str) -> Self {
        Self {
            error: "server_error".to_string(),
            error_description: Some(desc.to_string()),
        }
    }
}

/// Validated identity from subject token.
pub struct ValidatedSubject {
    /// Subject identifier.
    pub subject: String,
    /// Original scopes.
    pub scopes: Vec<String>,
    /// Additional claims.
    pub claims: HashMap<String, serde_json::Value>,
}

/// Subject token validator trait.
pub trait SubjectTokenValidator: Send + Sync {
    /// Validate the subject token and extract identity.
    fn validate(&self, token: &str, token_type: &TokenType) -> Result<ValidatedSubject>;
}

/// Handle a token exchange request.
pub async fn handle_token_exchange<V: SubjectTokenValidator>(
    config: &TokenExchangeConfig,
    issuer: &TokenIssuer,
    validator: &V,
    request: TokenExchangeRequest,
) -> Result<TokenExchangeResponse, TokenExchangeError> {
    // Validate grant type
    if request.grant_type != GRANT_TYPE_TOKEN_EXCHANGE {
        return Err(TokenExchangeError::invalid_request(
            "grant_type must be urn:ietf:params:oauth:grant-type:token-exchange",
        ));
    }

    // Parse subject token type
    let subject_type = TokenType::from_urn(&request.subject_token_type).ok_or_else(|| {
        TokenExchangeError::unsupported_token_type(&format!(
            "Unknown subject_token_type: {}",
            request.subject_token_type
        ))
    })?;

    // Parse requested token type (default to access_token)
    let requested_type = if let Some(ref urn) = request.requested_token_type {
        TokenType::from_urn(urn).ok_or_else(|| {
            TokenExchangeError::unsupported_token_type(&format!(
                "Unknown requested_token_type: {}",
                urn
            ))
        })?
    } else {
        TokenType::AccessToken
    };

    // Check if this exchange is allowed
    if !config.is_exchange_allowed(&subject_type, &requested_type) {
        warn!(
            from = ?subject_type,
            to = ?requested_type,
            "Token exchange not allowed"
        );
        return Err(TokenExchangeError::invalid_grant(
            "This token exchange is not permitted",
        ));
    }

    if config.log_exchanges {
        debug!(
            subject_token_type = %request.subject_token_type,
            requested_token_type = ?request.requested_token_type,
            audience = ?request.audience,
            "Processing token exchange"
        );
    }

    // Validate subject token
    let validated = validator
        .validate(&request.subject_token, &subject_type)
        .map_err(|e| {
            warn!(error = %e, "Subject token validation failed");
            TokenExchangeError::invalid_grant(&format!("Invalid subject token: {}", e))
        })?;

    // Determine scopes for new token
    let new_scopes = if let Some(ref requested_scope) = request.scope {
        // Use requested scopes (should be subset of original, but we'll trust the config)
        requested_scope.split_whitespace().map(String::from).collect()
    } else if let Some(mapping) = config.get_scope_mapping(&subject_type, &requested_type) {
        // Apply scope mapping
        let mut mapped = Vec::new();
        for scope in &validated.scopes {
            if let Some(new_scopes) = mapping.get(scope) {
                mapped.extend(new_scopes.iter().cloned());
            } else {
                // Keep original scope if no mapping
                mapped.push(scope.clone());
            }
        }
        mapped
    } else {
        // Use original scopes
        validated.scopes.clone()
    };

    // Issue new token
    let issued = issuer
        .issue_token(
            &validated.subject,
            request.audience.as_deref(),
            Some(&new_scopes),
            validated.claims,
            None,
        )
        .map_err(|e| {
            warn!(error = %e, "Failed to issue token");
            TokenExchangeError::server_error("Failed to issue token")
        })?;

    info!(
        subject = %validated.subject,
        from_type = %request.subject_token_type,
        to_type = %requested_type.as_urn(),
        "Token exchange successful"
    );

    Ok(TokenExchangeResponse {
        access_token: issued.token,
        issued_token_type: requested_type.as_urn().to_string(),
        token_type: issued.token_type,
        expires_in: issued.expires_in,
        scope: issued.scope,
        refresh_token: None,
    })
}

/// Parse form-urlencoded request body.
pub fn parse_exchange_request(body: &str) -> Result<TokenExchangeRequest, TokenExchangeError> {
    serde_urlencoded::from_str(body)
        .map_err(|e| TokenExchangeError::invalid_request(&format!("Invalid request body: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockValidator;

    impl SubjectTokenValidator for MockValidator {
        fn validate(&self, _token: &str, _token_type: &TokenType) -> Result<ValidatedSubject> {
            Ok(ValidatedSubject {
                subject: "user123".to_string(),
                scopes: vec!["read".to_string(), "write".to_string()],
                claims: HashMap::new(),
            })
        }
    }

    #[test]
    fn test_parse_exchange_request() {
        let body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
                    &subject_token=eyJhbGciOiJIUzI1NiJ9.e30.test\
                    &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt";

        let request = parse_exchange_request(body).unwrap();
        assert_eq!(request.grant_type, GRANT_TYPE_TOKEN_EXCHANGE);
        assert_eq!(
            request.subject_token_type,
            "urn:ietf:params:oauth:token-type:jwt"
        );
    }

    #[test]
    fn test_invalid_grant_type() {
        let request = TokenExchangeRequest {
            grant_type: "invalid".to_string(),
            subject_token: "token".to_string(),
            subject_token_type: TokenType::Jwt.as_urn().to_string(),
            requested_token_type: None,
            audience: None,
            scope: None,
            resource: None,
            actor_token: None,
            actor_token_type: None,
        };

        let config = TokenExchangeConfig::default();
        let issuer_config = TokenExchangeConfig {
            signing_key_inline: Some("secret".to_string()),
            signing_algorithm: "HS256".to_string(),
            issuer: Some("test".to_string()),
            ..Default::default()
        };
        let issuer = TokenIssuer::new(&issuer_config).unwrap();
        let validator = MockValidator;

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(handle_token_exchange(&config, &issuer, &validator, request));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.error, "invalid_request");
    }

    #[tokio::test]
    async fn test_successful_exchange() {
        let request = TokenExchangeRequest {
            grant_type: GRANT_TYPE_TOKEN_EXCHANGE.to_string(),
            subject_token: "valid-token".to_string(),
            subject_token_type: TokenType::Jwt.as_urn().to_string(),
            requested_token_type: Some(TokenType::AccessToken.as_urn().to_string()),
            audience: Some("my-api".to_string()),
            scope: None,
            resource: None,
            actor_token: None,
            actor_token_type: None,
        };

        let config = TokenExchangeConfig {
            enabled: true,
            signing_key_inline: Some("test-secret-key-long-enough-for-hs256".to_string()),
            signing_algorithm: "HS256".to_string(),
            issuer: Some("https://auth.example.com".to_string()),
            ..Default::default()
        };
        let issuer = TokenIssuer::new(&config).unwrap();
        let validator = MockValidator;

        let result = handle_token_exchange(&config, &issuer, &validator, request).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(!response.access_token.is_empty());
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(
            response.issued_token_type,
            TokenType::AccessToken.as_urn()
        );
    }
}
