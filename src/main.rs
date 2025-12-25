//! Sentinel Authentication Agent
//!
//! This agent provides authentication for the Sentinel proxy,
//! supporting JWT/Bearer tokens, API keys, and Basic auth.

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Duration, Utc};
use clap::Parser;
use jsonwebtoken::{decode, DecodingKey, TokenData, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn};

use sentinel_agent_protocol::{
    AgentHandler, AgentResult, AgentServer, Decision, Mutations,
    RequestHeadersEvent, ResponseHeadersEvent,
};

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "sentinel-auth-agent")]
#[command(about = "Authentication agent for Sentinel reverse proxy")]
struct Args {
    /// Path to Unix socket
    #[arg(long, default_value = "/tmp/sentinel-auth.sock", env = "AGENT_SOCKET")]
    socket: PathBuf,

    /// JWT secret key (for HS256)
    #[arg(long, env = "JWT_SECRET")]
    jwt_secret: Option<String>,

    /// JWT public key file (for RS256/ES256)
    #[arg(long, env = "JWT_PUBLIC_KEY")]
    jwt_public_key: Option<PathBuf>,

    /// JWT algorithm (HS256, RS256, ES256)
    #[arg(long, default_value = "HS256", env = "JWT_ALGORITHM")]
    jwt_algorithm: String,

    /// JWT issuer to validate
    #[arg(long, env = "JWT_ISSUER")]
    jwt_issuer: Option<String>,

    /// JWT audience to validate
    #[arg(long, env = "JWT_AUDIENCE")]
    jwt_audience: Option<String>,

    /// API keys (comma-separated key:name pairs)
    #[arg(long, env = "API_KEYS")]
    api_keys: Option<String>,

    /// API key header name
    #[arg(long, default_value = "X-API-Key", env = "API_KEY_HEADER")]
    api_key_header: String,

    /// Basic auth users (comma-separated user:pass pairs)
    #[arg(long, env = "BASIC_AUTH_USERS")]
    basic_auth_users: Option<String>,

    /// Header to add with user ID
    #[arg(long, default_value = "X-User-Id", env = "USER_ID_HEADER")]
    user_id_header: String,

    /// Header to add with auth method
    #[arg(long, default_value = "X-Auth-Method", env = "AUTH_METHOD_HEADER")]
    auth_method_header: String,

    /// Enable verbose logging
    #[arg(short, long, env = "AUTH_VERBOSE")]
    verbose: bool,

    /// Fail open (allow on auth error)
    #[arg(long, env = "FAIL_OPEN")]
    fail_open: bool,
}

/// Authentication method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    Jwt,
    ApiKey,
    Basic,
    None,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::Jwt => write!(f, "jwt"),
            AuthMethod::ApiKey => write!(f, "api_key"),
            AuthMethod::Basic => write!(f, "basic"),
            AuthMethod::None => write!(f, "none"),
        }
    }
}

/// Authenticated identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub method: AuthMethod,
    pub claims: HashMap<String, serde_json::Value>,
}

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: Option<String>,
    pub iss: Option<String>,
    pub aud: Option<serde_json::Value>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// API key info
#[derive(Debug, Clone)]
pub struct ApiKeyInfo {
    pub key: String,
    pub name: String,
}

/// Basic auth user
#[derive(Debug, Clone)]
pub struct BasicAuthUser {
    pub username: String,
    pub password_hash: String,
}

/// Authentication agent configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub jwt_secret: Option<Vec<u8>>,
    pub jwt_public_key: Option<DecodingKey>,
    pub jwt_algorithm: Algorithm,
    pub jwt_issuer: Option<String>,
    pub jwt_audience: Option<String>,
    pub api_keys: HashMap<String, ApiKeyInfo>,
    pub api_key_header: String,
    pub basic_auth_users: HashMap<String, BasicAuthUser>,
    pub user_id_header: String,
    pub auth_method_header: String,
    pub fail_open: bool,
}

impl AuthConfig {
    pub fn from_args(args: &Args) -> Result<Self> {
        // Parse JWT algorithm
        let jwt_algorithm = match args.jwt_algorithm.to_uppercase().as_str() {
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            "RS256" => Algorithm::RS256,
            "RS384" => Algorithm::RS384,
            "RS512" => Algorithm::RS512,
            "ES256" => Algorithm::ES256,
            "ES384" => Algorithm::ES384,
            _ => return Err(anyhow!("Unsupported JWT algorithm: {}", args.jwt_algorithm)),
        };

        // Parse JWT secret/key
        let jwt_secret = args.jwt_secret.as_ref().map(|s| s.as_bytes().to_vec());
        let jwt_public_key = if let Some(path) = &args.jwt_public_key {
            let key_data = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read JWT public key: {:?}", path))?;
            Some(DecodingKey::from_rsa_pem(key_data.as_bytes())
                .or_else(|_| DecodingKey::from_ec_pem(key_data.as_bytes()))
                .context("Failed to parse JWT public key")?)
        } else {
            None
        };

        // Parse API keys
        let mut api_keys = HashMap::new();
        if let Some(keys_str) = &args.api_keys {
            for pair in keys_str.split(',') {
                let pair = pair.trim();
                if let Some((key, name)) = pair.split_once(':') {
                    api_keys.insert(
                        key.trim().to_string(),
                        ApiKeyInfo {
                            key: key.trim().to_string(),
                            name: name.trim().to_string(),
                        },
                    );
                }
            }
        }

        // Parse basic auth users
        let mut basic_auth_users = HashMap::new();
        if let Some(users_str) = &args.basic_auth_users {
            for pair in users_str.split(',') {
                let pair = pair.trim();
                if let Some((user, pass)) = pair.split_once(':') {
                    basic_auth_users.insert(
                        user.trim().to_string(),
                        BasicAuthUser {
                            username: user.trim().to_string(),
                            password_hash: pass.trim().to_string(),
                        },
                    );
                }
            }
        }

        Ok(Self {
            jwt_secret,
            jwt_public_key,
            jwt_algorithm,
            jwt_issuer: args.jwt_issuer.clone(),
            jwt_audience: args.jwt_audience.clone(),
            api_keys,
            api_key_header: args.api_key_header.clone(),
            basic_auth_users,
            user_id_header: args.user_id_header.clone(),
            auth_method_header: args.auth_method_header.clone(),
            fail_open: args.fail_open,
        })
    }
}

/// Authentication agent
pub struct AuthAgent {
    config: AuthConfig,
}

impl AuthAgent {
    pub fn new(config: AuthConfig) -> Self {
        Self { config }
    }

    /// Authenticate a request
    pub fn authenticate(&self, headers: &[(String, String)]) -> Result<Identity> {
        // Convert headers to HashMap for easier lookup
        let header_map: HashMap<&str, &str> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        // 1. Try JWT Bearer token
        if let Some(auth_header) = header_map.get("authorization").or(header_map.get("Authorization")) {
            if auth_header.starts_with("Bearer ") || auth_header.starts_with("bearer ") {
                let token = &auth_header[7..];
                if let Ok(identity) = self.validate_jwt(token) {
                    return Ok(identity);
                }
            }

            // 2. Try Basic auth
            if auth_header.starts_with("Basic ") || auth_header.starts_with("basic ") {
                let credentials = &auth_header[6..];
                if let Ok(identity) = self.validate_basic_auth(credentials) {
                    return Ok(identity);
                }
            }
        }

        // 3. Try API key
        let api_key_header_lower = self.config.api_key_header.to_lowercase();
        for (key, value) in headers {
            if key.to_lowercase() == api_key_header_lower {
                if let Ok(identity) = self.validate_api_key(value) {
                    return Ok(identity);
                }
            }
        }

        Err(anyhow!("No valid authentication credentials found"))
    }

    /// Validate JWT token
    fn validate_jwt(&self, token: &str) -> Result<Identity> {
        let decoding_key = if let Some(ref secret) = self.config.jwt_secret {
            DecodingKey::from_secret(secret)
        } else if let Some(ref key) = self.config.jwt_public_key {
            key.clone()
        } else {
            return Err(anyhow!("No JWT secret or public key configured"));
        };

        let mut validation = Validation::new(self.config.jwt_algorithm);

        if let Some(ref issuer) = self.config.jwt_issuer {
            validation.set_issuer(&[issuer]);
        } else {
            validation.validate_iss = false;
        }

        if let Some(ref audience) = self.config.jwt_audience {
            validation.set_audience(&[audience]);
        } else {
            validation.validate_aud = false;
        }

        let token_data: TokenData<JwtClaims> = decode(token, &decoding_key, &validation)
            .context("JWT validation failed")?;

        let claims = token_data.claims;
        let user_id = claims.sub.clone().unwrap_or_else(|| "unknown".to_string());

        let mut claims_map = HashMap::new();
        if let Some(sub) = &claims.sub {
            claims_map.insert("sub".to_string(), serde_json::Value::String(sub.clone()));
        }
        if let Some(iss) = &claims.iss {
            claims_map.insert("iss".to_string(), serde_json::Value::String(iss.clone()));
        }
        for (k, v) in claims.extra {
            claims_map.insert(k, v);
        }

        Ok(Identity {
            id: user_id,
            method: AuthMethod::Jwt,
            claims: claims_map,
        })
    }

    /// Validate Basic auth credentials
    fn validate_basic_auth(&self, credentials: &str) -> Result<Identity> {
        let decoded = BASE64.decode(credentials)
            .context("Invalid base64 in Basic auth")?;
        let auth_str = String::from_utf8(decoded)
            .context("Invalid UTF-8 in Basic auth")?;

        let (username, password) = auth_str
            .split_once(':')
            .ok_or_else(|| anyhow!("Invalid Basic auth format"))?;

        let user = self.config.basic_auth_users
            .get(username)
            .ok_or_else(|| anyhow!("User not found"))?;

        // Simple password check (in production, use bcrypt or similar)
        if password != user.password_hash {
            return Err(anyhow!("Invalid password"));
        }

        Ok(Identity {
            id: username.to_string(),
            method: AuthMethod::Basic,
            claims: HashMap::from([
                ("username".to_string(), serde_json::Value::String(username.to_string())),
            ]),
        })
    }

    /// Validate API key
    fn validate_api_key(&self, api_key: &str) -> Result<Identity> {
        let key_info = self.config.api_keys
            .get(api_key)
            .ok_or_else(|| anyhow!("Invalid API key"))?;

        Ok(Identity {
            id: key_info.name.clone(),
            method: AuthMethod::ApiKey,
            claims: HashMap::from([
                ("api_key_name".to_string(), serde_json::Value::String(key_info.name.clone())),
            ]),
        })
    }
}

#[async_trait::async_trait]
impl AgentHandler for AuthAgent {
    async fn on_request_headers(
        &self,
        event: RequestHeadersEvent,
    ) -> AgentResult<(Decision, Mutations)> {
        let headers: Vec<(String, String)> = event.headers.clone();

        match self.authenticate(&headers) {
            Ok(identity) => {
                info!(
                    user_id = %identity.id,
                    method = %identity.method,
                    "Authentication successful"
                );

                let mut mutations = Mutations::default();
                mutations.request_headers.push((
                    self.config.user_id_header.clone(),
                    identity.id.clone(),
                ));
                mutations.request_headers.push((
                    self.config.auth_method_header.clone(),
                    identity.method.to_string(),
                ));

                // Add claims as headers
                for (key, value) in &identity.claims {
                    if let serde_json::Value::String(s) = value {
                        mutations.request_headers.push((
                            format!("X-Auth-Claim-{}", key),
                            s.clone(),
                        ));
                    }
                }

                Ok((Decision::Allow, mutations))
            }
            Err(e) => {
                debug!("Authentication failed: {}", e);

                if self.config.fail_open {
                    warn!("Authentication failed but fail_open is enabled, allowing request");
                    Ok((Decision::Allow, Mutations::default()))
                } else {
                    let mut mutations = Mutations::default();
                    mutations.response_headers.push((
                        "WWW-Authenticate".to_string(),
                        "Bearer realm=\"sentinel\"".to_string(),
                    ));
                    Ok((Decision::Block { status_code: 401 }, mutations))
                }
            }
        }
    }

    async fn on_response_headers(
        &self,
        _event: ResponseHeadersEvent,
    ) -> AgentResult<(Decision, Mutations)> {
        Ok((Decision::Allow, Mutations::default()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("{}={},sentinel_agent_protocol=info", env!("CARGO_CRATE_NAME"), log_level))
        .json()
        .init();

    info!("Starting Sentinel Auth Agent");

    // Build configuration
    let config = AuthConfig::from_args(&args)?;

    info!(
        jwt_configured = config.jwt_secret.is_some() || config.jwt_public_key.is_some(),
        api_keys_count = config.api_keys.len(),
        basic_auth_users_count = config.basic_auth_users.len(),
        fail_open = config.fail_open,
        "Configuration loaded"
    );

    // Create agent
    let agent = AuthAgent::new(config);

    // Remove existing socket if present
    if args.socket.exists() {
        std::fs::remove_file(&args.socket)?;
    }

    // Start agent server
    info!(socket = ?args.socket, "Starting agent server");
    let server = AgentServer::new(agent);
    server.serve_unix(&args.socket).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AuthConfig {
        let mut api_keys = HashMap::new();
        api_keys.insert(
            "test-key-123".to_string(),
            ApiKeyInfo {
                key: "test-key-123".to_string(),
                name: "test-api".to_string(),
            },
        );

        let mut basic_auth_users = HashMap::new();
        basic_auth_users.insert(
            "testuser".to_string(),
            BasicAuthUser {
                username: "testuser".to_string(),
                password_hash: "testpass".to_string(),
            },
        );

        AuthConfig {
            jwt_secret: Some(b"test-secret-key-at-least-32-chars".to_vec()),
            jwt_public_key: None,
            jwt_algorithm: Algorithm::HS256,
            jwt_issuer: None,
            jwt_audience: None,
            api_keys,
            api_key_header: "X-API-Key".to_string(),
            basic_auth_users,
            user_id_header: "X-User-Id".to_string(),
            auth_method_header: "X-Auth-Method".to_string(),
            fail_open: false,
        }
    }

    #[test]
    fn test_api_key_auth() {
        let config = test_config();
        let agent = AuthAgent::new(config);

        let headers = vec![
            ("X-API-Key".to_string(), "test-key-123".to_string()),
        ];

        let result = agent.authenticate(&headers);
        assert!(result.is_ok());

        let identity = result.unwrap();
        assert_eq!(identity.method, AuthMethod::ApiKey);
        assert_eq!(identity.id, "test-api");
    }

    #[test]
    fn test_basic_auth() {
        let config = test_config();
        let agent = AuthAgent::new(config);

        // Base64 encode "testuser:testpass"
        let credentials = BASE64.encode("testuser:testpass");
        let headers = vec![
            ("Authorization".to_string(), format!("Basic {}", credentials)),
        ];

        let result = agent.authenticate(&headers);
        assert!(result.is_ok());

        let identity = result.unwrap();
        assert_eq!(identity.method, AuthMethod::Basic);
        assert_eq!(identity.id, "testuser");
    }

    #[test]
    fn test_invalid_api_key() {
        let config = test_config();
        let agent = AuthAgent::new(config);

        let headers = vec![
            ("X-API-Key".to_string(), "invalid-key".to_string()),
        ];

        let result = agent.authenticate(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_auth() {
        let config = test_config();
        let agent = AuthAgent::new(config);

        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        let result = agent.authenticate(&headers);
        assert!(result.is_err());
    }
}
