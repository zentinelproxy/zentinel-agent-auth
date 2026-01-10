//! Sentinel Authentication Agent
//!
//! This agent provides authentication for the Sentinel proxy,
//! supporting JWT/Bearer tokens, API keys, Basic auth, and SAML SSO.

mod saml;
mod session;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Parser;
use jsonwebtoken::{decode, DecodingKey, TokenData, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AgentServer, AuditMetadata, ConfigureEvent, HeaderOp,
    RequestBodyChunkEvent, RequestHeadersEvent, ResponseHeadersEvent,
};
use std::sync::RwLock;

use saml::{SamlConfig, SamlConfigJson, SamlProvider};
use session::{spawn_cleanup_task, SessionId, SessionStore, DEFAULT_CLEANUP_INTERVAL_SECS};

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
    Saml,
    None,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::Jwt => write!(f, "jwt"),
            AuthMethod::ApiKey => write!(f, "api_key"),
            AuthMethod::Basic => write!(f, "basic"),
            AuthMethod::Saml => write!(f, "saml"),
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

/// JSON configuration for dynamic reconfiguration via on_configure()
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct AuthConfigJson {
    /// JWT secret key (for HS256)
    pub jwt_secret: Option<String>,
    /// JWT algorithm (HS256, RS256, ES256)
    pub jwt_algorithm: Option<String>,
    /// JWT issuer to validate
    pub jwt_issuer: Option<String>,
    /// JWT audience to validate
    pub jwt_audience: Option<String>,
    /// API keys as key:name pairs
    #[serde(default)]
    pub api_keys: Vec<String>,
    /// API key header name
    pub api_key_header: Option<String>,
    /// Basic auth users as user:pass pairs
    #[serde(default)]
    pub basic_auth_users: Vec<String>,
    /// Header to add with user ID
    pub user_id_header: Option<String>,
    /// Header to add with auth method
    pub auth_method_header: Option<String>,
    /// Fail open (allow on auth error)
    #[serde(default)]
    pub fail_open: bool,
    /// SAML configuration
    #[serde(default)]
    pub saml: SamlConfigJson,
}

impl AuthConfig {
    fn from_args(args: &Args) -> Result<Self> {
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
    config: RwLock<AuthConfig>,
    /// SAML provider (optional, created when SAML is enabled).
    saml_provider: RwLock<Option<SamlProvider>>,
    /// Session store (optional, created when SAML is enabled).
    session_store: Option<Arc<SessionStore>>,
    /// SAML configuration.
    saml_config: RwLock<SamlConfig>,
    /// Buffered request body for ACS endpoint.
    acs_body_buffer: RwLock<HashMap<String, Vec<u8>>>,
}

impl AuthAgent {
    pub fn new(config: AuthConfig, session_store: Option<Arc<SessionStore>>) -> Self {
        Self {
            config: RwLock::new(config),
            saml_provider: RwLock::new(None),
            session_store,
            saml_config: RwLock::new(SamlConfig::default()),
            acs_body_buffer: RwLock::new(HashMap::new()),
        }
    }

    /// Initialize or update SAML provider.
    pub fn configure_saml(&self, config: SamlConfig) -> Result<()> {
        if config.enabled {
            let provider = SamlProvider::new(config.clone())?;
            let mut guard = self.saml_provider.write()
                .map_err(|_| anyhow!("SAML provider lock poisoned"))?;
            *guard = Some(provider);
        }

        let mut saml_cfg = self.saml_config.write()
            .map_err(|_| anyhow!("SAML config lock poisoned"))?;
        *saml_cfg = config;

        Ok(())
    }

    /// Get SAML config.
    fn get_saml_config(&self) -> Result<SamlConfig> {
        self.saml_config.read()
            .map(|c| c.clone())
            .map_err(|_| anyhow!("SAML config lock poisoned"))
    }

    /// Try to authenticate via SAML session cookie.
    fn authenticate_saml_session(&self, headers: &HashMap<String, Vec<String>>) -> Result<Identity> {
        let saml_config = self.get_saml_config()?;

        if !saml_config.enabled {
            return Err(anyhow!("SAML not enabled"));
        }

        let session_store = self.session_store.as_ref()
            .ok_or_else(|| anyhow!("Session store not initialized"))?;

        // Get cookie header
        let cookie_header = headers.iter()
            .find(|(k, _)| k.to_lowercase() == "cookie")
            .and_then(|(_, v)| v.first())
            .ok_or_else(|| anyhow!("No cookie header"))?;

        // Parse session ID from cookie
        let session_id_str = saml_config.parse_session_cookie(cookie_header)
            .ok_or_else(|| anyhow!("No session cookie found"))?;

        let session_id = SessionId::from_hex(&session_id_str)
            .ok_or_else(|| anyhow!("Invalid session ID format"))?;

        // Look up session
        let session = session_store.get(session_id)?
            .ok_or_else(|| anyhow!("Session not found or expired"))?;

        // Build identity from session
        let mut claims = HashMap::new();

        for (attr_name, values) in &session.attributes {
            if let Some(first) = values.first() {
                claims.insert(attr_name.clone(), serde_json::Value::String(first.clone()));
            }
        }

        claims.insert(
            "idp_entity_id".to_string(),
            serde_json::Value::String(session.idp_entity_id.clone()),
        );

        if let Some(ref format) = session.name_id_format {
            claims.insert(
                "name_id_format".to_string(),
                serde_json::Value::String(format.clone()),
            );
        }

        Ok(Identity {
            id: session.user_id.clone(),
            method: AuthMethod::Saml,
            claims,
        })
    }

    /// Build SAML redirect response to IdP.
    fn build_saml_redirect(&self, original_uri: &str) -> Result<AgentResponse> {
        let provider_guard = self.saml_provider.read()
            .map_err(|_| anyhow!("SAML provider lock poisoned"))?;

        let provider = provider_guard.as_ref()
            .ok_or_else(|| anyhow!("SAML provider not initialized"))?;

        let redirect_url = provider.create_authn_request(Some(original_uri))?;

        Ok(AgentResponse::block(302, None)
            .add_response_header(HeaderOp::Set {
                name: "Location".to_string(),
                value: redirect_url,
            })
            .with_audit(AuditMetadata {
                tags: vec!["auth".to_string(), "saml".to_string(), "redirect".to_string()],
                ..Default::default()
            }))
    }

    /// Build response headers with SAML session attributes.
    fn build_saml_identity_response(&self, identity: &Identity, saml_config: &SamlConfig, user_id_header: &str, auth_method_header: &str) -> AgentResponse {
        let mut response = AgentResponse::default_allow()
            .add_request_header(HeaderOp::Set {
                name: user_id_header.to_string(),
                value: identity.id.clone(),
            })
            .add_request_header(HeaderOp::Set {
                name: auth_method_header.to_string(),
                value: identity.method.to_string(),
            });

        // Add mapped attribute headers
        for (attr_name, header_name) in &saml_config.attribute_mapping {
            if let Some(serde_json::Value::String(value)) = identity.claims.get(attr_name) {
                response = response.add_request_header(HeaderOp::Set {
                    name: header_name.clone(),
                    value: value.clone(),
                });
            }
        }

        // Add all claims as X-Auth-Claim-* headers
        for (key, value) in &identity.claims {
            if let serde_json::Value::String(s) = value {
                response = response.add_request_header(HeaderOp::Set {
                    name: format!("X-Auth-Claim-{}", key),
                    value: s.clone(),
                });
            }
        }

        response.with_audit(AuditMetadata {
            tags: vec!["auth".to_string(), "saml".to_string()],
            ..Default::default()
        })
    }

    /// Reconfigure the agent with new settings
    pub fn reconfigure(&self, json_config: AuthConfigJson) -> Result<()> {
        let mut config = self.config.write().map_err(|_| anyhow!("Failed to acquire write lock"))?;

        // Update JWT secret
        if let Some(secret) = json_config.jwt_secret {
            config.jwt_secret = Some(secret.as_bytes().to_vec());
        }

        // Update JWT algorithm
        if let Some(alg) = json_config.jwt_algorithm {
            config.jwt_algorithm = match alg.to_uppercase().as_str() {
                "HS256" => Algorithm::HS256,
                "HS384" => Algorithm::HS384,
                "HS512" => Algorithm::HS512,
                "RS256" => Algorithm::RS256,
                "RS384" => Algorithm::RS384,
                "RS512" => Algorithm::RS512,
                "ES256" => Algorithm::ES256,
                "ES384" => Algorithm::ES384,
                _ => return Err(anyhow!("Unsupported JWT algorithm: {}", alg)),
            };
        }

        // Update JWT issuer/audience
        if let Some(issuer) = json_config.jwt_issuer {
            config.jwt_issuer = Some(issuer);
        }
        if let Some(audience) = json_config.jwt_audience {
            config.jwt_audience = Some(audience);
        }

        // Update API keys
        if !json_config.api_keys.is_empty() {
            config.api_keys.clear();
            for pair in json_config.api_keys {
                if let Some((key, name)) = pair.split_once(':') {
                    config.api_keys.insert(
                        key.trim().to_string(),
                        ApiKeyInfo {
                            key: key.trim().to_string(),
                            name: name.trim().to_string(),
                        },
                    );
                }
            }
        }

        // Update API key header
        if let Some(header) = json_config.api_key_header {
            config.api_key_header = header;
        }

        // Update basic auth users
        if !json_config.basic_auth_users.is_empty() {
            config.basic_auth_users.clear();
            for pair in json_config.basic_auth_users {
                if let Some((user, pass)) = pair.split_once(':') {
                    config.basic_auth_users.insert(
                        user.trim().to_string(),
                        BasicAuthUser {
                            username: user.trim().to_string(),
                            password_hash: pass.trim().to_string(),
                        },
                    );
                }
            }
        }

        // Update headers
        if let Some(header) = json_config.user_id_header {
            config.user_id_header = header;
        }
        if let Some(header) = json_config.auth_method_header {
            config.auth_method_header = header;
        }

        // Update fail_open
        config.fail_open = json_config.fail_open;

        drop(config);

        // Update SAML config
        let mut saml_config = self.get_saml_config().unwrap_or_default();
        json_config.saml.apply_to(&mut saml_config);
        self.configure_saml(saml_config)?;

        info!("Reconfigured auth agent");
        Ok(())
    }

    /// Authenticate a request
    pub fn authenticate(&self, headers: &HashMap<String, Vec<String>>) -> Result<Identity> {
        let config = self.config.read().map_err(|_| anyhow!("Failed to acquire read lock"))?;
        // Helper to get first header value (case-insensitive)
        let get_header = |name: &str| -> Option<&str> {
            let name_lower = name.to_lowercase();
            for (key, values) in headers {
                if key.to_lowercase() == name_lower {
                    return values.first().map(|s| s.as_str());
                }
            }
            None
        };

        // 1. Try JWT Bearer token
        if let Some(auth_header) = get_header("authorization") {
            if auth_header.starts_with("Bearer ") || auth_header.starts_with("bearer ") {
                let token = &auth_header[7..];
                if let Ok(identity) = Self::validate_jwt(&config, token) {
                    return Ok(identity);
                }
            }

            // 2. Try Basic auth
            if auth_header.starts_with("Basic ") || auth_header.starts_with("basic ") {
                let credentials = &auth_header[6..];
                if let Ok(identity) = Self::validate_basic_auth(&config, credentials) {
                    return Ok(identity);
                }
            }
        }

        // 3. Try API key
        if let Some(api_key) = get_header(&config.api_key_header) {
            if let Ok(identity) = Self::validate_api_key(&config, api_key) {
                return Ok(identity);
            }
        }

        Err(anyhow!("No valid authentication credentials found"))
    }

    /// Validate JWT token
    fn validate_jwt(config: &AuthConfig, token: &str) -> Result<Identity> {
        let decoding_key = if let Some(ref secret) = config.jwt_secret {
            DecodingKey::from_secret(secret)
        } else if let Some(ref key) = config.jwt_public_key {
            key.clone()
        } else {
            return Err(anyhow!("No JWT secret or public key configured"));
        };

        let mut validation = Validation::new(config.jwt_algorithm);

        // Set issuer validation
        if let Some(ref issuer) = config.jwt_issuer {
            validation.set_issuer(&[issuer]);
        } else {
            validation.iss = None;
        }

        // Set audience validation
        if let Some(ref audience) = config.jwt_audience {
            validation.set_audience(&[audience]);
        } else {
            validation.aud = None;
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
    fn validate_basic_auth(config: &AuthConfig, credentials: &str) -> Result<Identity> {
        let decoded = BASE64.decode(credentials)
            .context("Invalid base64 in Basic auth")?;
        let auth_str = String::from_utf8(decoded)
            .context("Invalid UTF-8 in Basic auth")?;

        let (username, password) = auth_str
            .split_once(':')
            .ok_or_else(|| anyhow!("Invalid Basic auth format"))?;

        let user = config.basic_auth_users
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
    fn validate_api_key(config: &AuthConfig, api_key: &str) -> Result<Identity> {
        let key_info = config.api_keys
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
    async fn on_configure(&self, event: ConfigureEvent) -> AgentResponse {
        let json_config: AuthConfigJson = match serde_json::from_value(event.config) {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!("Failed to parse auth config: {}, using defaults", e);
                return AgentResponse::default_allow();
            }
        };

        if let Err(e) = self.reconfigure(json_config) {
            warn!("Failed to reconfigure auth agent: {}", e);
            return AgentResponse::block(500, Some(format!("Configuration error: {}", e)));
        }

        info!("Auth agent configured via on_configure");
        AgentResponse::default_allow()
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        // Get config values we need before authentication
        let (user_id_header, auth_method_header, fail_open) = {
            let config = match self.config.read() {
                Ok(c) => c,
                Err(_) => {
                    warn!("Failed to acquire config lock");
                    return AgentResponse::block(500, Some("Internal error".to_string()));
                }
            };
            (
                config.user_id_header.clone(),
                config.auth_method_header.clone(),
                config.fail_open,
            )
        };

        // Get SAML config
        let saml_config = match self.get_saml_config() {
            Ok(c) => c,
            Err(_) => SamlConfig::default(),
        };

        // Get request path for SAML path matching
        let request_path = event.headers.get("path")
            .or_else(|| event.headers.get(":path"))
            .and_then(|v| v.first())
            .map(|s| s.as_str())
            .unwrap_or("/");

        // Check if this is the SAML ACS endpoint (POST)
        if saml_config.enabled && saml_config.is_acs_path(request_path) {
            let method = event.headers.get("method")
                .or_else(|| event.headers.get(":method"))
                .and_then(|v| v.first())
                .map(|s| s.to_uppercase())
                .unwrap_or_default();

            if method == "POST" {
                // Need to read the body to get SAMLResponse
                debug!("SAML ACS endpoint hit, waiting for body");

                // Store correlation ID for body buffering
                if let Ok(mut buffer) = self.acs_body_buffer.write() {
                    buffer.insert(event.metadata.correlation_id.clone(), Vec::new());
                }

                // Return needs_more_data to signal we need the request body
                return AgentResponse::needs_more_data();
            }
        }

        // Try SAML session authentication first if enabled
        if saml_config.enabled && saml_config.should_protect_path(request_path) {
            if let Ok(identity) = self.authenticate_saml_session(&event.headers) {
                info!(
                    user_id = %identity.id,
                    method = %identity.method,
                    "SAML session authentication successful"
                );
                return self.build_saml_identity_response(&identity, &saml_config, &user_id_header, &auth_method_header);
            }
        }

        // Try other authentication methods (JWT, API Key, Basic)
        match self.authenticate(&event.headers) {
            Ok(identity) => {
                info!(
                    user_id = %identity.id,
                    method = %identity.method,
                    "Authentication successful"
                );

                let mut response = AgentResponse::default_allow()
                    .add_request_header(HeaderOp::Set {
                        name: user_id_header,
                        value: identity.id.clone(),
                    })
                    .add_request_header(HeaderOp::Set {
                        name: auth_method_header,
                        value: identity.method.to_string(),
                    });

                // Add claims as headers
                for (key, value) in &identity.claims {
                    if let serde_json::Value::String(s) = value {
                        response = response.add_request_header(HeaderOp::Set {
                            name: format!("X-Auth-Claim-{}", key),
                            value: s.clone(),
                        });
                    }
                }

                response.with_audit(AuditMetadata {
                    tags: vec!["auth".to_string(), identity.method.to_string()],
                    ..Default::default()
                })
            }
            Err(e) => {
                debug!("Authentication failed: {}", e);

                // If SAML is enabled and path should be protected, redirect to IdP
                if saml_config.enabled && saml_config.should_protect_path(request_path) {
                    info!(path = %request_path, "No valid auth, redirecting to SAML IdP");
                    match self.build_saml_redirect(request_path) {
                        Ok(response) => return response,
                        Err(e) => {
                            warn!(error = %e, "Failed to create SAML redirect");
                        }
                    }
                }

                if fail_open {
                    warn!("Authentication failed but fail_open is enabled, allowing request");
                    AgentResponse::default_allow()
                        .with_audit(AuditMetadata {
                            tags: vec!["auth".to_string(), "fail_open".to_string()],
                            reason_codes: vec!["AUTH_FAILED_OPEN".to_string()],
                            ..Default::default()
                        })
                } else {
                    AgentResponse::block(401, Some("Unauthorized".to_string()))
                        .add_response_header(HeaderOp::Set {
                            name: "WWW-Authenticate".to_string(),
                            value: "Bearer realm=\"sentinel\"".to_string(),
                        })
                        .with_audit(AuditMetadata {
                            tags: vec!["auth".to_string(), "blocked".to_string()],
                            reason_codes: vec!["AUTH_REQUIRED".to_string()],
                            ..Default::default()
                        })
                }
            }
        }
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        // Buffer the chunk (data is already a String)
        if let Ok(mut buffer) = self.acs_body_buffer.write() {
            if let Some(body) = buffer.get_mut(&event.correlation_id) {
                body.extend_from_slice(event.data.as_bytes());
            }
        }

        // If this is the last chunk, process the SAML response
        if event.is_last {
            let body_data = {
                let mut buffer = match self.acs_body_buffer.write() {
                    Ok(b) => b,
                    Err(_) => {
                        return AgentResponse::block(500, Some("Internal error".to_string()));
                    }
                };
                buffer.remove(&event.correlation_id).unwrap_or_default()
            };

            // Parse form data to get SAMLResponse (body_data is bytes)
            let body_str = match String::from_utf8(body_data) {
                Ok(s) => s,
                Err(_) => {
                    return AgentResponse::block(400, Some("Invalid request body".to_string()));
                }
            };

            // Parse URL-encoded form data
            let mut saml_response: Option<String> = None;
            let mut relay_state: Option<String> = None;

            for pair in body_str.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    let decoded_value = urlencoding::decode(value)
                        .map(|s| s.into_owned())
                        .unwrap_or_else(|_| value.to_string());

                    if key == "SAMLResponse" {
                        saml_response = Some(decoded_value);
                    } else if key == "RelayState" {
                        relay_state = Some(decoded_value);
                    }
                }
            }

            let saml_response = match saml_response {
                Some(r) => r,
                None => {
                    return AgentResponse::block(400, Some("Missing SAMLResponse".to_string()));
                }
            };

            // Get SAML provider and session store
            let saml_config = match self.get_saml_config() {
                Ok(c) => c,
                Err(_) => {
                    return AgentResponse::block(500, Some("SAML not configured".to_string()));
                }
            };

            let session_store = match &self.session_store {
                Some(s) => s,
                None => {
                    return AgentResponse::block(500, Some("Session store not initialized".to_string()));
                }
            };

            let provider_guard = match self.saml_provider.read() {
                Ok(g) => g,
                Err(_) => {
                    return AgentResponse::block(500, Some("Internal error".to_string()));
                }
            };

            let provider = match provider_guard.as_ref() {
                Some(p) => p,
                None => {
                    return AgentResponse::block(500, Some("SAML provider not initialized".to_string()));
                }
            };

            // Process the SAML response
            let assertion = match provider.process_response(&saml_response, session_store) {
                Ok(a) => a,
                Err(e) => {
                    warn!(error = %e, "SAML assertion validation failed");
                    return AgentResponse::block(401, Some("SAML authentication failed".to_string()))
                        .with_audit(AuditMetadata {
                            tags: vec!["auth".to_string(), "saml".to_string(), "failed".to_string()],
                            reason_codes: vec!["SAML_VALIDATION_FAILED".to_string()],
                            ..Default::default()
                        });
                }
            };

            // Create session
            let session = match provider.create_session(assertion, session_store, None) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "Failed to create SAML session");
                    return AgentResponse::block(500, Some("Failed to create session".to_string()));
                }
            };

            info!(
                user_id = %session.user_id,
                session_id = %session.id,
                "SAML authentication successful, session created"
            );

            // Build redirect response with session cookie
            let redirect_url = relay_state.unwrap_or_else(|| "/".to_string());
            let cookie = saml_config.build_cookie(&session.id.to_hex());

            AgentResponse::block(302, None)
                .add_response_header(HeaderOp::Set {
                    name: "Location".to_string(),
                    value: redirect_url,
                })
                .add_response_header(HeaderOp::Set {
                    name: "Set-Cookie".to_string(),
                    value: cookie,
                })
                .with_audit(AuditMetadata {
                    tags: vec!["auth".to_string(), "saml".to_string(), "session_created".to_string()],
                    ..Default::default()
                })
        } else {
            // Not the last chunk, continue buffering
            AgentResponse::needs_more_data()
        }
    }

    async fn on_response_headers(&self, _event: ResponseHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
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

    // Initialize session store for SAML (will be configured via on_configure)
    // Use a default path, can be overridden via SAML config
    let session_store_path = std::env::var("SAML_SESSION_STORE_PATH")
        .unwrap_or_else(|_| "/var/lib/sentinel-auth/sessions.redb".to_string());

    let session_store = match SessionStore::open(
        PathBuf::from(&session_store_path),
        SamlConfig::default().session_ttl_secs,
    ) {
        Ok(store) => {
            info!(path = %session_store_path, "Session store initialized");
            Some(Arc::new(store))
        }
        Err(e) => {
            warn!(
                error = %e,
                path = %session_store_path,
                "Failed to initialize session store, SAML will be unavailable"
            );
            None
        }
    };

    // Spawn background cleanup task if session store is available
    let _cleanup_handle = session_store.as_ref().map(|store| {
        info!("Starting session cleanup task");
        spawn_cleanup_task(Arc::clone(store), DEFAULT_CLEANUP_INTERVAL_SECS)
    });

    // Create agent with session store
    let agent = AuthAgent::new(config, session_store);

    // Start agent server
    info!(socket = ?args.socket, "Starting agent server");
    let server = AgentServer::new(
        "sentinel-auth-agent",
        args.socket,
        Box::new(agent),
    );
    server.run().await.map_err(|e| anyhow::anyhow!("{}", e))?;

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
        let agent = AuthAgent::new(config, None);

        let mut headers = HashMap::new();
        headers.insert("X-API-Key".to_string(), vec!["test-key-123".to_string()]);

        let result = agent.authenticate(&headers);
        assert!(result.is_ok());

        let identity = result.unwrap();
        assert_eq!(identity.method, AuthMethod::ApiKey);
        assert_eq!(identity.id, "test-api");
    }

    #[test]
    fn test_basic_auth() {
        let config = test_config();
        let agent = AuthAgent::new(config, None);

        // Base64 encode "testuser:testpass"
        let credentials = BASE64.encode("testuser:testpass");
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), vec![format!("Basic {}", credentials)]);

        let result = agent.authenticate(&headers);
        assert!(result.is_ok());

        let identity = result.unwrap();
        assert_eq!(identity.method, AuthMethod::Basic);
        assert_eq!(identity.id, "testuser");
    }

    #[test]
    fn test_invalid_api_key() {
        let config = test_config();
        let agent = AuthAgent::new(config, None);

        let mut headers = HashMap::new();
        headers.insert("X-API-Key".to_string(), vec!["invalid-key".to_string()]);

        let result = agent.authenticate(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_auth() {
        let config = test_config();
        let agent = AuthAgent::new(config, None);

        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), vec!["application/json".to_string()]);

        let result = agent.authenticate(&headers);
        assert!(result.is_err());
    }
}
