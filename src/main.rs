//! Zentinel Authentication Agent
//!
//! This agent provides authentication for the Zentinel proxy,
//! supporting JWT/Bearer tokens, API keys, Basic auth, SAML SSO,
//! OIDC/OAuth 2.0, mTLS client certificates, and Cedar policy authorization.

mod authz;
mod credentials;
mod exchange;
mod mtls;
mod oidc;
mod saml;
mod scim;
mod secret;
mod session;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Parser;
use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, CounterMetric, DrainReason,
    GrpcAgentServerV2, HealthStatus, MetricsReport, ShutdownReason, UdsAgentServerV2,
};
use zentinel_agent_protocol::EventType;
use zentinel_agent_protocol::{
    AgentResponse, AuditMetadata, HeaderOp, RequestBodyChunkEvent, RequestHeadersEvent,
    ResponseHeadersEvent,
};

use authz::{AuthzConfig, AuthzConfigJson, AuthzRequest, CedarAuthorizer};
use credentials::{
    dummy_bcrypt_check, find_api_key, parse_api_keys, parse_basic_auth_users, ApiKeyInfo,
    BasicAuthUser, PasswordCheck,
};
use exchange::{
    parse_exchange_request, SubjectTokenValidator, TokenExchangeConfig, TokenExchangeConfigJson,
    TokenIssuer, TokenType, ValidatedSubject,
};
use mtls::{validate_client_cert, MtlsConfig, MtlsConfigJson};
use oidc::{validate_oidc_token, JwksCache, JwksSettings, OidcConfig, OidcConfigJson};
use saml::{SamlConfig, SamlConfigJson, SamlProvider};
use scim::{
    handle_scim_body, handle_scim_delete, handle_scim_get, match_scim_route, scim_error_response,
    ScimConfig, ScimConfigJson, ScimRoute, ScimUserStore,
};
use session::{spawn_cleanup_task, SessionId, SessionStore, DEFAULT_CLEANUP_INTERVAL_SECS};

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "zentinel-auth-agent")]
#[command(about = "Authentication agent for Zentinel reverse proxy")]
struct Args {
    /// Path to Unix socket (for UDS transport)
    #[arg(long, default_value = "/tmp/zentinel-auth.sock", env = "AGENT_SOCKET")]
    socket: PathBuf,

    /// gRPC server address (e.g., "[::1]:50051" or "0.0.0.0:50051")
    /// If specified, the agent will use gRPC transport instead of UDS
    #[arg(long, env = "GRPC_ADDRESS")]
    grpc_address: Option<String>,

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

    /// Basic auth users (comma-separated user:bcrypt-hash pairs)
    #[arg(long, env = "BASIC_AUTH_USERS")]
    basic_auth_users: Option<String>,

    /// Accept plain-text Basic auth passwords (not recommended)
    #[arg(long, env = "BASIC_AUTH_ALLOW_PLAINTEXT")]
    basic_auth_allow_plaintext: bool,

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
    Oidc,
    Mtls,
    None,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::Jwt => write!(f, "jwt"),
            AuthMethod::ApiKey => write!(f, "api_key"),
            AuthMethod::Basic => write!(f, "basic"),
            AuthMethod::Saml => write!(f, "saml"),
            AuthMethod::Oidc => write!(f, "oidc"),
            AuthMethod::Mtls => write!(f, "mtls"),
            AuthMethod::None => write!(f, "none"),
        }
    }
}

/// Authenticated identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub method: AuthMethod,
    /// Claims forwarded as `X-Auth-Claim-*` headers (string values only).
    pub claims: HashMap<String, serde_json::Value>,
    /// The verified claims with their JSON types (arrays, numbers, ...) for
    /// authorization, when they differ from `claims`.
    pub raw_claims: Option<HashMap<String, serde_json::Value>>,
}

impl Identity {
    /// Claims as authorization should see them.
    pub fn authz_claims(&self) -> &HashMap<String, serde_json::Value> {
        self.raw_claims.as_ref().unwrap_or(&self.claims)
    }
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

/// Authentication agent configuration
pub struct AuthConfig {
    pub jwt_secret: Option<Vec<u8>>,
    pub jwt_public_key: Option<DecodingKey>,
    pub jwt_algorithm: Algorithm,
    pub jwt_issuer: Option<String>,
    pub jwt_audience: Option<String>,
    pub api_keys: Vec<ApiKeyInfo>,
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
    /// Basic auth users as user:bcrypt-hash pairs
    #[serde(default)]
    pub basic_auth_users: Vec<String>,
    /// Accept plain-text passwords in `basic-auth-users`
    #[serde(default)]
    pub basic_auth_allow_plaintext: bool,
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
    /// OIDC/OAuth 2.0 configuration
    #[serde(default)]
    pub oidc: OidcConfigJson,
    /// mTLS configuration
    #[serde(default)]
    pub mtls: MtlsConfigJson,
    /// Cedar authorization configuration
    #[serde(default)]
    pub authz: AuthzConfigJson,
    /// Token exchange configuration
    #[serde(default)]
    pub token_exchange: TokenExchangeConfigJson,
    /// SCIM provisioning configuration
    #[serde(default)]
    pub scim: ScimConfigJson,
}

/// Modules that trust an identity, or grant a privilege, they never verify.
///
/// Each is refused rather than run until its verification exists:
///
/// - **SAML** accepts an assertion without checking its XML signature, so
///   anyone can post a forged response and get a session for any NameID.
/// - **mTLS** reads a certificate from a request header and never verifies
///   its chain against a trust anchor, so a self-signed certificate with any
///   subject authenticates as that subject.
/// - **Token exchange** mints tokens signed by this agent's key with whatever
///   scope and audience the caller asks for: `allowed-exchanges` and the
///   scope mapping are never checked.
///
/// They could only be enabled through the `config { }` block of the agent's
/// Zentinel configuration, which the proxy did not deliver until
/// zentinelproxy/zentinel#593. Delivering it would have made them reachable,
/// so a configuration that enables any of them is now rejected, and nothing
/// of it is applied. See zentinelproxy/zentinel-agent-auth#6.
pub const UNVERIFIED_MODULES_ISSUE: &str =
    "https://github.com/zentinelproxy/zentinel-agent-auth/issues/6";

/// Refuse a configuration that enables a module listed at
/// [`UNVERIFIED_MODULES_ISSUE`].
fn refuse_unverified_modules(config: &AuthConfigJson) -> Result<()> {
    let enabled: Vec<&str> = [
        ("saml", config.saml.enabled),
        ("mtls", config.mtls.enabled),
        ("token-exchange", config.token_exchange.enabled),
    ]
    .into_iter()
    .filter(|(_, enabled)| *enabled == Some(true))
    .map(|(name, _)| name)
    .collect();

    if enabled.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "refusing to enable {}: these modules do not verify what they trust \
         (SAML signatures, mTLS certificate chains, token-exchange grants) and \
         are disabled until they do; see {}",
        enabled.join(", "),
        UNVERIFIED_MODULES_ISSUE
    ))
}

/// The error for a module enabled by any path other than `on_configure`.
fn unverified_module_error(module: &str) -> anyhow::Error {
    anyhow!(
        "refusing to enable {module}: it does not verify what it trusts and is \
         disabled until it does; see {UNVERIFIED_MODULES_ISSUE}"
    )
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
            Some(
                DecodingKey::from_rsa_pem(key_data.as_bytes())
                    .or_else(|_| DecodingKey::from_ec_pem(key_data.as_bytes()))
                    .context("Failed to parse JWT public key")?,
            )
        } else {
            None
        };

        // Parse API keys
        let api_keys = args
            .api_keys
            .as_deref()
            .map(|keys| parse_api_keys(keys.split(',')))
            .unwrap_or_default();

        // Parse basic auth users
        let basic_auth_users = match &args.basic_auth_users {
            Some(users) => {
                parse_basic_auth_users(users.split(','), args.basic_auth_allow_plaintext)?
            }
            None => HashMap::new(),
        };

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

/// Outcome of authenticating a SCIM request.
#[derive(Debug, PartialEq, Eq)]
enum ScimAuth {
    Allowed,
    Unauthenticated,
    MissingScope,
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
    /// Buffered request body for ACS/token exchange endpoint.
    body_buffer: RwLock<HashMap<String, Vec<u8>>>,
    /// OIDC configuration.
    oidc_config: RwLock<OidcConfig>,
    /// OIDC JWKS cache (initialized when OIDC is enabled).
    jwks_cache: RwLock<Option<Arc<JwksCache>>>,
    /// mTLS configuration.
    mtls_config: RwLock<MtlsConfig>,
    /// Cedar authorization configuration.
    authz_config: RwLock<AuthzConfig>,
    /// Cedar authorizer (initialized when authz is enabled).
    authorizer: RwLock<Option<CedarAuthorizer>>,
    /// Token exchange configuration.
    exchange_config: RwLock<TokenExchangeConfig>,
    /// Token issuer (initialized when exchange is enabled).
    token_issuer: RwLock<Option<TokenIssuer>>,
    /// SCIM provisioning configuration.
    scim_config: RwLock<ScimConfig>,
    /// SCIM user store (initialized when SCIM is enabled).
    scim_store: Option<Arc<ScimUserStore>>,
    /// Metrics: total requests processed.
    requests_total: AtomicU64,
    /// Metrics: SCIM provisioning requests.
    scim_requests_total: AtomicU64,
    /// Metrics: successful authentications.
    auth_success_total: AtomicU64,
    /// Metrics: failed authentications.
    auth_failure_total: AtomicU64,
    /// Metrics: blocked requests (authorization denied).
    blocked_total: AtomicU64,
    /// Health state: true if healthy.
    is_healthy: RwLock<bool>,
}

impl AuthAgent {
    pub fn new(
        config: AuthConfig,
        session_store: Option<Arc<SessionStore>>,
        scim_store: Option<Arc<ScimUserStore>>,
    ) -> Self {
        Self {
            config: RwLock::new(config),
            saml_provider: RwLock::new(None),
            session_store,
            saml_config: RwLock::new(SamlConfig::default()),
            body_buffer: RwLock::new(HashMap::new()),
            oidc_config: RwLock::new(OidcConfig::default()),
            jwks_cache: RwLock::new(None),
            mtls_config: RwLock::new(MtlsConfig::default()),
            authz_config: RwLock::new(AuthzConfig::default()),
            authorizer: RwLock::new(None),
            exchange_config: RwLock::new(TokenExchangeConfig::default()),
            token_issuer: RwLock::new(None),
            scim_config: RwLock::new(ScimConfig::default()),
            scim_store,
            requests_total: AtomicU64::new(0),
            scim_requests_total: AtomicU64::new(0),
            auth_success_total: AtomicU64::new(0),
            auth_failure_total: AtomicU64::new(0),
            blocked_total: AtomicU64::new(0),
            is_healthy: RwLock::new(true),
        }
    }

    /// Initialize or update SAML provider.
    pub fn configure_saml(&self, config: SamlConfig) -> Result<()> {
        if config.enabled {
            return Err(unverified_module_error("saml"));
        }
        if config.enabled {
            let provider = SamlProvider::new(config.clone())?;
            let mut guard = self
                .saml_provider
                .write()
                .map_err(|_| anyhow!("SAML provider lock poisoned"))?;
            *guard = Some(provider);
        }

        let mut saml_cfg = self
            .saml_config
            .write()
            .map_err(|_| anyhow!("SAML config lock poisoned"))?;
        *saml_cfg = config;

        Ok(())
    }

    /// Get SAML config.
    fn get_saml_config(&self) -> Result<SamlConfig> {
        self.saml_config
            .read()
            .map(|c| c.clone())
            .map_err(|_| anyhow!("SAML config lock poisoned"))
    }

    /// Configure OIDC provider.
    ///
    /// Never waits for the JWKS endpoint: the keys are fetched in a
    /// background task with a bounded timeout, and tokens are rejected until
    /// they have loaded.
    pub fn configure_oidc(&self, config: OidcConfig) -> Result<()> {
        config
            .validate()
            .map_err(|e| anyhow!("OIDC config validation failed: {}", e))?;

        let cache = if config.enabled {
            let cache = Arc::new(JwksCache::new(
                config.jwks_url.clone(),
                JwksSettings {
                    refresh_interval: Duration::from_secs(config.jwks_refresh_secs),
                    min_refetch_interval: Duration::from_secs(config.jwks_min_refetch_secs),
                    fetch_timeout: Duration::from_millis(config.jwks_fetch_timeout_ms),
                },
            )?);
            cache.spawn_refresh();
            info!(issuer = %config.issuer, "OIDC configured");
            Some(cache)
        } else {
            None
        };
        {
            let mut guard = self
                .jwks_cache
                .write()
                .map_err(|_| anyhow!("JWKS cache lock poisoned"))?;
            *guard = cache;
        }

        let mut oidc_cfg = self
            .oidc_config
            .write()
            .map_err(|_| anyhow!("OIDC config lock poisoned"))?;
        *oidc_cfg = config;

        Ok(())
    }

    /// Get OIDC config.
    fn get_oidc_config(&self) -> Result<OidcConfig> {
        self.oidc_config
            .read()
            .map(|c| c.clone())
            .map_err(|_| anyhow!("OIDC config lock poisoned"))
    }

    /// Configure mTLS.
    pub fn configure_mtls(&self, config: MtlsConfig) -> Result<()> {
        if config.enabled {
            return Err(unverified_module_error("mtls"));
        }
        if let Err(e) = config.validate() {
            return Err(anyhow!("mTLS config validation failed: {}", e));
        }

        let mut mtls_cfg = self
            .mtls_config
            .write()
            .map_err(|_| anyhow!("mTLS config lock poisoned"))?;
        *mtls_cfg = config;

        info!("mTLS configured");
        Ok(())
    }

    /// Get mTLS config.
    fn get_mtls_config(&self) -> Result<MtlsConfig> {
        self.mtls_config
            .read()
            .map(|c| c.clone())
            .map_err(|_| anyhow!("mTLS config lock poisoned"))
    }

    /// Configure Cedar authorization.
    ///
    /// A policy that does not parse is an error and changes nothing; it
    /// never leaves authorization switched off.
    pub fn configure_authz(&self, config: AuthzConfig) -> Result<()> {
        let authorizer = if config.enabled {
            let authorizer = CedarAuthorizer::new(&config)
                .map_err(|e| anyhow!("Cedar authorization config rejected: {}", e))?;
            info!("Cedar authorization configured");
            Some(authorizer)
        } else {
            None
        };
        {
            let mut guard = self
                .authorizer
                .write()
                .map_err(|_| anyhow!("Authorizer lock poisoned"))?;
            *guard = authorizer;
        }

        let mut authz_cfg = self
            .authz_config
            .write()
            .map_err(|_| anyhow!("Authz config lock poisoned"))?;
        *authz_cfg = config;

        Ok(())
    }

    /// Get authz config.
    fn get_authz_config(&self) -> Result<AuthzConfig> {
        self.authz_config
            .read()
            .map(|c| c.clone())
            .map_err(|_| anyhow!("Authz config lock poisoned"))
    }

    /// Configure token exchange.
    pub fn configure_exchange(&self, config: TokenExchangeConfig) -> Result<()> {
        if config.enabled {
            return Err(unverified_module_error("token-exchange"));
        }
        if config.enabled {
            let issuer = TokenIssuer::new(&config)?;
            let mut guard = self
                .token_issuer
                .write()
                .map_err(|_| anyhow!("Token issuer lock poisoned"))?;
            *guard = Some(issuer);
            info!(endpoint = %config.endpoint_path, "Token exchange configured");
        }

        let mut exchange_cfg = self
            .exchange_config
            .write()
            .map_err(|_| anyhow!("Exchange config lock poisoned"))?;
        *exchange_cfg = config;

        Ok(())
    }

    /// Get exchange config.
    fn get_exchange_config(&self) -> Result<TokenExchangeConfig> {
        self.exchange_config
            .read()
            .map(|c| c.clone())
            .map_err(|_| anyhow!("Exchange config lock poisoned"))
    }

    /// Configure SCIM provisioning.
    pub fn configure_scim(&self, config: ScimConfig) -> Result<()> {
        if config.enabled {
            if let Err(e) = config.validate() {
                return Err(anyhow!("SCIM config validation failed: {}", e));
            }
            info!(base_path = %config.base_path, "SCIM provisioning configured");
        }

        let mut scim_cfg = self
            .scim_config
            .write()
            .map_err(|_| anyhow!("SCIM config lock poisoned"))?;
        *scim_cfg = config;

        Ok(())
    }

    /// Get SCIM config.
    fn get_scim_config(&self) -> Result<ScimConfig> {
        self.scim_config
            .read()
            .map(|c| c.clone())
            .map_err(|_| anyhow!("SCIM config lock poisoned"))
    }

    /// Validate a SCIM bearer token against the configured static token.
    fn validate_scim_bearer_token(&self, auth_header: &str) -> Result<()> {
        let token = if auth_header.starts_with("Bearer ") || auth_header.starts_with("bearer ") {
            &auth_header[7..]
        } else {
            return Err(anyhow!("Missing Bearer prefix"));
        };

        let scim_config = self.get_scim_config()?;
        if let Some(ref expected) = scim_config.bearer_token {
            if secret::secrets_equal(token.as_bytes(), expected.as_bytes()) {
                return Ok(());
            }
        }

        Err(anyhow!("Invalid SCIM bearer token"))
    }

    /// Try to authenticate via mTLS client certificate.
    fn authenticate_mtls(&self, headers: &HashMap<String, Vec<String>>) -> Result<Identity> {
        let mtls_config = self.get_mtls_config()?;

        if !mtls_config.enabled {
            return Err(anyhow!("mTLS not enabled"));
        }

        // Get certificate from header
        let cert_header = headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == mtls_config.client_cert_header.to_lowercase())
            .and_then(|(_, v)| v.first())
            .ok_or_else(|| anyhow!("No client certificate header"))?;

        let identity = validate_client_cert(&mtls_config, cert_header)?;

        let mut claims = HashMap::new();
        for (k, v) in identity.claims {
            claims.insert(k, serde_json::Value::String(v));
        }

        Ok(Identity {
            id: identity.user_id,
            method: AuthMethod::Mtls,
            raw_claims: None,
            claims,
        })
    }

    /// Try to authenticate via OIDC token.
    async fn authenticate_oidc(&self, token: &str) -> Result<Identity> {
        self.authenticate_oidc_with_scopes(token)
            .await
            .map(|(identity, _)| identity)
    }

    /// Authenticate via OIDC token, also returning the token's scopes.
    async fn authenticate_oidc_with_scopes(&self, token: &str) -> Result<(Identity, Vec<String>)> {
        let oidc_config = self.get_oidc_config()?;

        if !oidc_config.enabled {
            return Err(anyhow!("OIDC not enabled"));
        }

        // Clone the Arc before the await to avoid holding the lock across await
        let jwks = {
            let jwks_guard = self
                .jwks_cache
                .read()
                .map_err(|_| anyhow!("JWKS cache lock poisoned"))?;
            jwks_guard
                .as_ref()
                .ok_or_else(|| anyhow!("JWKS cache not initialized"))?
                .clone()
        };

        let identity = validate_oidc_token(&oidc_config, &jwks, token).await?;

        let mut claims = HashMap::new();
        for (k, v) in identity.claims {
            claims.insert(k, serde_json::Value::String(v));
        }

        Ok((
            Identity {
                id: identity.user_id,
                method: AuthMethod::Oidc,
                raw_claims: Some(identity.raw_claims),
                claims,
            },
            identity.scopes,
        ))
    }

    /// Authenticate a request to the SCIM endpoint: the static bearer token,
    /// or (with `use-oidc-auth`) an OIDC token carrying the SCIM scope.
    async fn authorize_scim(
        &self,
        scim_config: &ScimConfig,
        auth_header: Option<&str>,
    ) -> ScimAuth {
        let Some(header) = auth_header else {
            return ScimAuth::Unauthenticated;
        };
        if self.validate_scim_bearer_token(header).is_ok() {
            return ScimAuth::Allowed;
        }
        if !scim_config.use_oidc_auth {
            return ScimAuth::Unauthenticated;
        }
        let Some(token) = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
        else {
            return ScimAuth::Unauthenticated;
        };
        let (identity, scopes) = match self.authenticate_oidc_with_scopes(token).await {
            Ok(v) => v,
            Err(_) => return ScimAuth::Unauthenticated,
        };
        // Refused by validate(), but never treat a missing scope as "any".
        let Some(required) = scim_config.oidc_scope() else {
            return ScimAuth::MissingScope;
        };
        if scopes.iter().any(|s| s == required) {
            ScimAuth::Allowed
        } else {
            warn!(
                user = %identity.id,
                required_scope = %required,
                "SCIM request refused: OIDC token lacks the SCIM scope"
            );
            ScimAuth::MissingScope
        }
    }

    /// Handle token exchange request body.
    async fn handle_exchange_body(
        &self,
        _correlation_id: &str,
        exchange_key: &str,
    ) -> AgentResponse {
        let body_data = {
            let mut buffer = match self.body_buffer.write() {
                Ok(b) => b,
                Err(_) => {
                    return AgentResponse::block(500, Some("Internal error".to_string()));
                }
            };
            buffer.remove(exchange_key).unwrap_or_default()
        };

        let body_str = match String::from_utf8(body_data) {
            Ok(s) => s,
            Err(_) => {
                return self
                    .exchange_error_response("invalid_request", "Invalid request body encoding");
            }
        };

        // Parse the request
        let request = match parse_exchange_request(&body_str) {
            Ok(r) => r,
            Err(e) => {
                return self.exchange_error_response(
                    &e.error,
                    e.error_description.as_deref().unwrap_or(""),
                );
            }
        };

        let _exchange_config = match self.get_exchange_config() {
            Ok(c) => c,
            Err(_) => {
                return self.exchange_error_response("server_error", "Configuration error");
            }
        };

        // Validate the subject token synchronously first
        let validated = {
            let validator = AuthAgentTokenValidator { agent: self };
            let token_type = match exchange::TokenType::from_urn(&request.subject_token_type) {
                Some(t) => t,
                None => {
                    return self.exchange_error_response(
                        "unsupported_token_type",
                        "Unknown subject_token_type",
                    );
                }
            };
            match validator.validate(&request.subject_token, &token_type) {
                Ok(v) => v,
                Err(e) => {
                    return self.exchange_error_response(
                        "invalid_grant",
                        &format!("Invalid subject token: {}", e),
                    );
                }
            }
        };

        // Issue new token
        let (token, expires_in, scope) = {
            let issuer_guard = match self.token_issuer.read() {
                Ok(g) => g,
                Err(_) => {
                    return self.exchange_error_response("server_error", "Internal error");
                }
            };

            let issuer = match issuer_guard.as_ref() {
                Some(i) => i,
                None => {
                    return self
                        .exchange_error_response("server_error", "Token exchange not configured");
                }
            };

            // Determine scopes
            let new_scopes: Vec<String> = if let Some(ref requested_scope) = request.scope {
                requested_scope
                    .split_whitespace()
                    .map(String::from)
                    .collect()
            } else {
                validated.scopes.clone()
            };

            match issuer.issue_token(
                &validated.subject,
                request.audience.as_deref(),
                Some(&new_scopes),
                validated.claims,
                None,
            ) {
                Ok(issued) => (issued.token, issued.expires_in, issued.scope),
                Err(e) => {
                    warn!(error = %e, "Failed to issue token");
                    return self.exchange_error_response("server_error", "Failed to issue token");
                }
            }
        };

        let requested_type = request
            .requested_token_type
            .as_deref()
            .and_then(exchange::TokenType::from_urn)
            .unwrap_or(exchange::TokenType::AccessToken);

        let response = exchange::TokenExchangeResponse {
            access_token: token,
            issued_token_type: requested_type.as_urn().to_string(),
            token_type: "Bearer".to_string(),
            expires_in,
            scope,
            refresh_token: None,
        };

        match serde_json::to_string(&response) {
            Ok(json_body) => {
                info!("Token exchange successful");

                AgentResponse::block(200, Some(json_body))
                    .add_response_header(HeaderOp::Set {
                        name: "Content-Type".to_string(),
                        value: "application/json".to_string(),
                    })
                    .with_audit(AuditMetadata {
                        tags: vec!["auth".to_string(), "token_exchange".to_string()],
                        ..Default::default()
                    })
            }
            Err(_) => self.exchange_error_response("server_error", "Failed to serialize response"),
        }
    }

    /// Build token exchange error response.
    fn exchange_error_response(&self, error: &str, description: &str) -> AgentResponse {
        let error_body = serde_json::json!({
            "error": error,
            "error_description": description
        });

        AgentResponse::block(400, Some(error_body.to_string()))
            .add_response_header(HeaderOp::Set {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            })
            .with_audit(AuditMetadata {
                tags: vec![
                    "auth".to_string(),
                    "token_exchange".to_string(),
                    "error".to_string(),
                ],
                reason_codes: vec![error.to_string()],
                ..Default::default()
            })
    }

    /// Check authorization using Cedar policies.
    fn check_authorization(&self, identity: &Identity, method: &str, path: &str) -> Result<bool> {
        let authz_config = self.get_authz_config()?;

        if !authz_config.enabled {
            return Ok(true); // Authorization not enabled, allow all
        }

        let authorizer_guard = self
            .authorizer
            .read()
            .map_err(|_| anyhow!("Authorizer lock poisoned"))?;

        // Enabled without a compiled policy set: fail closed.
        let authorizer = authorizer_guard
            .as_ref()
            .ok_or_else(|| anyhow!("Authorizer not initialized"))?;

        let auth_method = identity.method.to_string();
        let decision = authorizer.is_authorized(&AuthzRequest {
            user_id: &identity.id,
            auth_method: &auth_method,
            method,
            path,
            claims: identity.authz_claims(),
        });

        if !decision.allowed {
            debug!(
                user = %identity.id,
                action = %method,
                resource = %path,
                reason = ?decision.reason,
                policies = ?decision.policy_ids,
                "Authorization denied"
            );
        }

        Ok(decision.allowed)
    }

    /// Try to authenticate via SAML session cookie.
    fn authenticate_saml_session(
        &self,
        headers: &HashMap<String, Vec<String>>,
    ) -> Result<Identity> {
        let saml_config = self.get_saml_config()?;

        if !saml_config.enabled {
            return Err(anyhow!("SAML not enabled"));
        }

        let session_store = self
            .session_store
            .as_ref()
            .ok_or_else(|| anyhow!("Session store not initialized"))?;

        // Get cookie header
        let cookie_header = headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "cookie")
            .and_then(|(_, v)| v.first())
            .ok_or_else(|| anyhow!("No cookie header"))?;

        // Parse session ID from cookie
        let session_id_str = saml_config
            .parse_session_cookie(cookie_header)
            .ok_or_else(|| anyhow!("No session cookie found"))?;

        let session_id = SessionId::from_hex(&session_id_str)
            .ok_or_else(|| anyhow!("Invalid session ID format"))?;

        // Look up session
        let session = session_store
            .get(session_id)?
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
            raw_claims: None,
            claims,
        })
    }

    /// Build SAML redirect response to IdP.
    fn build_saml_redirect(&self, original_uri: &str) -> Result<AgentResponse> {
        let provider_guard = self
            .saml_provider
            .read()
            .map_err(|_| anyhow!("SAML provider lock poisoned"))?;

        let provider = provider_guard
            .as_ref()
            .ok_or_else(|| anyhow!("SAML provider not initialized"))?;

        let redirect_url = provider.create_authn_request(Some(original_uri))?;

        Ok(AgentResponse::block(302, None)
            .add_response_header(HeaderOp::Set {
                name: "Location".to_string(),
                value: redirect_url,
            })
            .with_audit(AuditMetadata {
                tags: vec![
                    "auth".to_string(),
                    "saml".to_string(),
                    "redirect".to_string(),
                ],
                ..Default::default()
            }))
    }

    /// Build response headers with SAML session attributes.
    fn build_saml_identity_response(
        &self,
        identity: &Identity,
        saml_config: &SamlConfig,
        user_id_header: &str,
        auth_method_header: &str,
    ) -> AgentResponse {
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

    /// Build response headers with identity and authorization check.
    fn build_identity_response(
        &self,
        identity: Identity,
        user_id_header: &str,
        auth_method_header: &str,
        request_method: &str,
        request_path: &str,
    ) -> AgentResponse {
        // Check authorization
        match self.check_authorization(&identity, request_method, request_path) {
            Ok(true) => {
                // Authorized - build success response
                let mut response = AgentResponse::default_allow()
                    .add_request_header(HeaderOp::Set {
                        name: user_id_header.to_string(),
                        value: identity.id.clone(),
                    })
                    .add_request_header(HeaderOp::Set {
                        name: auth_method_header.to_string(),
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
            Ok(false) => {
                // Not authorized
                warn!(
                    user = %identity.id,
                    method = %request_method,
                    path = %request_path,
                    "Authorization denied"
                );
                AgentResponse::block(403, Some("Forbidden".to_string())).with_audit(AuditMetadata {
                    tags: vec!["auth".to_string(), "authz_denied".to_string()],
                    reason_codes: vec!["AUTHORIZATION_DENIED".to_string()],
                    ..Default::default()
                })
            }
            Err(e) => {
                warn!(error = %e, "Authorization check failed");
                AgentResponse::block(500, Some("Authorization error".to_string())).with_audit(
                    AuditMetadata {
                        tags: vec!["auth".to_string(), "authz_error".to_string()],
                        reason_codes: vec!["AUTHORIZATION_ERROR".to_string()],
                        ..Default::default()
                    },
                )
            }
        }
    }

    /// Check a configuration completely before any of it is applied.
    ///
    /// [`AuthAgent::reconfigure`] applies settings one at a time, so a
    /// refusal halfway would leave a mix of old and new; everything that can
    /// be refused is refused here first.
    fn preflight(&self, json_config: &AuthConfigJson) -> Result<()> {
        refuse_unverified_modules(json_config)?;

        let mut oidc_config = self.get_oidc_config().unwrap_or_default();
        json_config.oidc.apply_to(&mut oidc_config);
        oidc_config
            .validate()
            .map_err(|e| anyhow!("OIDC config validation failed: {}", e))?;

        Self::parse_json_basic_auth_users(json_config)?;

        let mut authz_config = self.get_authz_config().unwrap_or_default();
        json_config.authz.apply_to(&mut authz_config);
        if authz_config.enabled {
            // Compiles the policies: a parse error rejects the configure.
            CedarAuthorizer::new(&authz_config)
                .map_err(|e| anyhow!("Cedar authorization config rejected: {}", e))?;
        }

        let mut scim_config = self.get_scim_config().unwrap_or_default();
        json_config.scim.apply_to(&mut scim_config);
        if scim_config.enabled {
            scim_config
                .validate()
                .map_err(|e| anyhow!("SCIM config validation failed: {}", e))?;
        }

        Ok(())
    }

    /// The Basic auth users of a configuration, if it sets any.
    fn parse_json_basic_auth_users(
        json_config: &AuthConfigJson,
    ) -> Result<Option<HashMap<String, BasicAuthUser>>> {
        if json_config.basic_auth_users.is_empty() {
            return Ok(None);
        }
        parse_basic_auth_users(
            json_config.basic_auth_users.iter().map(String::as_str),
            json_config.basic_auth_allow_plaintext,
        )
        .map(Some)
    }

    /// Reconfigure the agent with new settings
    pub fn reconfigure(&self, json_config: AuthConfigJson) -> Result<()> {
        // Checked before anything is written.
        self.preflight(&json_config)?;
        let basic_auth_users = Self::parse_json_basic_auth_users(&json_config)?;

        let mut config = self
            .config
            .write()
            .map_err(|_| anyhow!("Failed to acquire write lock"))?;

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
            config.api_keys = parse_api_keys(json_config.api_keys.iter().map(String::as_str));
        }

        // Update API key header
        if let Some(header) = json_config.api_key_header {
            config.api_key_header = header;
        }

        // Update basic auth users (parsed before the lock was taken)
        if let Some(users) = basic_auth_users {
            config.basic_auth_users = users;
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

        // Update OIDC config (the JWKS is fetched in the background)
        let mut oidc_config = self.get_oidc_config().unwrap_or_default();
        json_config.oidc.apply_to(&mut oidc_config);
        self.configure_oidc(oidc_config)?;

        // Update SAML config
        let mut saml_config = self.get_saml_config().unwrap_or_default();
        json_config.saml.apply_to(&mut saml_config);
        self.configure_saml(saml_config)?;

        // Update mTLS config
        let mut mtls_config = self.get_mtls_config().unwrap_or_default();
        json_config.mtls.apply_to(&mut mtls_config);
        self.configure_mtls(mtls_config)?;

        // Update authz config
        let mut authz_config = self.get_authz_config().unwrap_or_default();
        json_config.authz.apply_to(&mut authz_config);
        self.configure_authz(authz_config)?;

        // Update token exchange config
        let mut exchange_config = self.get_exchange_config().unwrap_or_default();
        json_config.token_exchange.apply_to(&mut exchange_config);
        self.configure_exchange(exchange_config)?;

        // Update SCIM config
        let mut scim_config = self.get_scim_config().unwrap_or_default();
        json_config.scim.apply_to(&mut scim_config);
        self.configure_scim(scim_config)?;

        info!("Reconfigured auth agent");
        Ok(())
    }

    /// Authenticate a request
    pub async fn authenticate(&self, headers: &HashMap<String, Vec<String>>) -> Result<Identity> {
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

        let pending_bcrypt = {
            let config = self
                .config
                .read()
                .map_err(|_| anyhow!("Failed to acquire read lock"))?;
            let mut pending = None;

            if let Some(auth_header) = get_header("authorization") {
                // 1. Try JWT Bearer token
                if auth_header.starts_with("Bearer ") || auth_header.starts_with("bearer ") {
                    let token = &auth_header[7..];
                    if let Ok(identity) = Self::validate_jwt(&config, token) {
                        return Ok(identity);
                    }
                }

                // 2. Try Basic auth
                if auth_header.starts_with("Basic ") || auth_header.starts_with("basic ") {
                    match Self::check_basic_auth(&config, &auth_header[6..]) {
                        BasicCheck::Valid(username) => return Ok(basic_identity(&username)),
                        BasicCheck::Invalid => {}
                        BasicCheck::NeedsBcrypt(job) => pending = Some(job),
                    }
                }
            }
            pending
        };

        // bcrypt takes 100+ ms: run it off the async worker threads.
        if let Some(job) = pending_bcrypt {
            let username = job.username.clone();
            let valid = tokio::task::spawn_blocking(move || job.run())
                .await
                .unwrap_or(false);
            if valid {
                return Ok(basic_identity(&username));
            }
        }

        // 3. Try API key
        let config = self
            .config
            .read()
            .map_err(|_| anyhow!("Failed to acquire read lock"))?;
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

        let token_data: TokenData<JwtClaims> =
            decode(token, &decoding_key, &validation).context("JWT validation failed")?;

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
            raw_claims: None,
            claims: claims_map,
        })
    }

    /// Check Basic auth credentials as far as possible without bcrypt.
    fn check_basic_auth(config: &AuthConfig, credentials: &str) -> BasicCheck {
        let Ok(decoded) = BASE64.decode(credentials.trim()) else {
            return BasicCheck::Invalid;
        };
        let Ok(auth_str) = String::from_utf8(decoded) else {
            return BasicCheck::Invalid;
        };
        let Some((username, password)) = auth_str.split_once(':') else {
            return BasicCheck::Invalid;
        };

        match config.basic_auth_users.get(username) {
            Some(user) => match user.quick_check(password) {
                Some(true) => BasicCheck::Valid(username.to_string()),
                Some(false) => BasicCheck::Invalid,
                None => BasicCheck::NeedsBcrypt(BcryptJob {
                    username: username.to_string(),
                    password: password.to_string(),
                    user: Some(user.clone()),
                }),
            },
            // An unknown user costs a bcrypt run too when bcrypt users
            // exist, so timing does not reveal which users exist.
            None if config
                .basic_auth_users
                .values()
                .any(|u| matches!(u.password, PasswordCheck::Bcrypt(_))) =>
            {
                BasicCheck::NeedsBcrypt(BcryptJob {
                    username: username.to_string(),
                    password: password.to_string(),
                    user: None,
                })
            }
            None => BasicCheck::Invalid,
        }
    }

    /// Validate API key
    fn validate_api_key(config: &AuthConfig, api_key: &str) -> Result<Identity> {
        let key_info =
            find_api_key(&config.api_keys, api_key).ok_or_else(|| anyhow!("Invalid API key"))?;

        Ok(Identity {
            id: key_info.name.clone(),
            method: AuthMethod::ApiKey,
            raw_claims: None,
            claims: HashMap::from([(
                "api_key_name".to_string(),
                serde_json::Value::String(key_info.name.clone()),
            )]),
        })
    }
}

/// Outcome of checking Basic credentials without bcrypt.
enum BasicCheck {
    Valid(String),
    Invalid,
    NeedsBcrypt(BcryptJob),
}

/// A bcrypt verification to run on a blocking thread.
struct BcryptJob {
    username: String,
    password: String,
    /// `None` for an unknown user: checked against a dummy hash.
    user: Option<BasicAuthUser>,
}

impl BcryptJob {
    fn run(self) -> bool {
        match self.user {
            Some(user) => user.bcrypt_check(&self.password),
            None => {
                dummy_bcrypt_check(&self.password);
                false
            }
        }
    }
}

fn basic_identity(username: &str) -> Identity {
    Identity {
        id: username.to_string(),
        method: AuthMethod::Basic,
        raw_claims: None,
        claims: HashMap::from([(
            "username".to_string(),
            serde_json::Value::String(username.to_string()),
        )]),
    }
}

/// Token validator for token exchange that uses the agent's existing validators.
struct AuthAgentTokenValidator<'a> {
    agent: &'a AuthAgent,
}

impl SubjectTokenValidator for AuthAgentTokenValidator<'_> {
    fn validate(&self, token: &str, token_type: &TokenType) -> Result<ValidatedSubject> {
        match token_type {
            TokenType::Jwt | TokenType::AccessToken | TokenType::IdToken => {
                // Try to validate as JWT using existing config
                let config = self
                    .agent
                    .config
                    .read()
                    .map_err(|_| anyhow!("Failed to acquire config lock"))?;

                let identity = AuthAgent::validate_jwt(&config, token)?;

                let mut claims = HashMap::new();
                for (k, v) in identity.claims {
                    claims.insert(k, v);
                }

                Ok(ValidatedSubject {
                    subject: identity.id,
                    scopes: claims
                        .get("scope")
                        .and_then(|v| v.as_str())
                        .map(|s| s.split_whitespace().map(String::from).collect())
                        .unwrap_or_default(),
                    claims,
                })
            }
            TokenType::Saml2 => {
                // SAML token validation would require the full SAML provider
                // For now, return an error - SAML exchange requires session-based flow
                Err(anyhow!("SAML token exchange requires ACS flow"))
            }
            TokenType::RefreshToken => Err(anyhow!("Refresh token exchange not supported")),
        }
    }
}

#[async_trait::async_trait]
impl AgentHandlerV2 for AuthAgent {
    /// Get agent capabilities for v2 protocol.
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new(
            "zentinel-auth-agent",
            "Zentinel Auth Agent",
            env!("CARGO_PKG_VERSION"),
        )
        .with_event(EventType::RequestHeaders)
        .with_event(EventType::RequestBodyChunk)
        .with_event(EventType::ResponseHeaders)
        .with_event(EventType::Configure)
        .with_features(AgentFeatures {
            streaming_body: true,
            websocket: false,
            guardrails: false,
            config_push: true,
            metrics_export: true,
            concurrent_requests: 100,
            cancellation: true,
            flow_control: false,
            health_reporting: true,
        })
    }

    /// Get current health status.
    fn health_status(&self) -> HealthStatus {
        let is_healthy = self.is_healthy.read().map(|guard| *guard).unwrap_or(false);

        if is_healthy {
            HealthStatus::healthy("zentinel-auth-agent")
        } else {
            HealthStatus::degraded(
                "zentinel-auth-agent",
                vec!["config_error".to_string()],
                1.5, // Increase timeout multiplier when degraded
            )
        }
    }

    /// Get current metrics report.
    fn metrics_report(&self) -> Option<MetricsReport> {
        let mut report = MetricsReport::new("zentinel-auth-agent", 10_000);

        report.counters.push(CounterMetric::new(
            "auth_requests_total",
            self.requests_total.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "auth_success_total",
            self.auth_success_total.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "auth_failure_total",
            self.auth_failure_total.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "auth_blocked_total",
            self.blocked_total.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "scim_requests_total",
            self.scim_requests_total.load(Ordering::Relaxed),
        ));
        let jwks_fetches = self
            .jwks_cache
            .read()
            .ok()
            .and_then(|c| c.as_ref().map(|c| c.fetch_count()))
            .unwrap_or(0);
        report
            .counters
            .push(CounterMetric::new("oidc_jwks_fetches_total", jwks_fetches));

        Some(report)
    }

    /// Handle configuration update (v2 signature).
    async fn on_configure(&self, config: serde_json::Value, _version: Option<String>) -> bool {
        let json_config: AuthConfigJson = match serde_json::from_value(config) {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!("Failed to parse auth config: {}, using defaults", e);
                return false;
            }
        };

        // A refused configuration changes nothing at all.
        if let Err(e) = self.preflight(&json_config) {
            error!("Configuration rejected: {}", e);
            return false;
        }

        // Applies everything, OIDC included. Nothing here waits for the
        // network: the JWKS is fetched in the background.
        if let Err(e) = self.reconfigure(json_config) {
            warn!("Failed to reconfigure auth agent: {}", e);
            if let Ok(mut healthy) = self.is_healthy.write() {
                *healthy = false;
            }
            return false;
        }

        if let Ok(mut healthy) = self.is_healthy.write() {
            *healthy = true;
        }

        info!("Auth agent configured via on_configure");
        true
    }

    /// Handle shutdown request.
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "Auth agent received shutdown request"
        );
        // Clean up any resources if needed
        // Session store cleanup is handled by the cleanup task
    }

    /// Handle drain request.
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            reason = ?reason,
            duration_ms = duration_ms,
            "Auth agent received drain request"
        );
        // Stop accepting new requests
        // Existing requests will complete
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        // Increment request counter
        self.requests_total.fetch_add(1, Ordering::Relaxed);

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
        let saml_config = self.get_saml_config().unwrap_or_default();

        // Get request path and method for matching. Zentinel moves the
        // `:path` and `:method` pseudo-headers into `uri` and `method` and
        // removes them from `headers`.
        let (request_path, request_method) = request_target(&event);
        let request_path = request_path.as_str();

        // Check if this is a SCIM provisioning endpoint
        let scim_config = self.get_scim_config().unwrap_or_default();
        if scim_config.enabled && scim_config.matches_path(request_path) {
            self.scim_requests_total.fetch_add(1, Ordering::Relaxed);

            // Authenticate the SCIM request (bearer token or OIDC)
            let auth_header = event
                .headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == "authorization")
                .and_then(|(_, v)| v.first())
                .cloned();

            match self
                .authorize_scim(&scim_config, auth_header.as_deref())
                .await
            {
                ScimAuth::Allowed => {}
                ScimAuth::Unauthenticated => return scim_error_response(401, "Unauthorized"),
                ScimAuth::MissingScope => {
                    return scim_error_response(403, "Token lacks the required SCIM scope")
                }
            }

            // Route the request
            if let Some(route) =
                match_scim_route(&scim_config.base_path, request_path, &request_method)
            {
                let scim_store = match &self.scim_store {
                    Some(s) => s,
                    None => return scim_error_response(503, "SCIM store not initialized"),
                };

                let base_url = scim_config.effective_base_url();

                match &route {
                    // GET and DELETE can be handled immediately (no body needed)
                    ScimRoute::GetUser(_) | ScimRoute::ListUsers => {
                        let query_string = request_path.split('?').nth(1);
                        return handle_scim_get(scim_store, &route, query_string, &base_url);
                    }
                    ScimRoute::DeleteUser(id) => {
                        return handle_scim_delete(scim_store, id);
                    }
                    // POST, PUT, PATCH need body buffering
                    ScimRoute::CreateUser | ScimRoute::ReplaceUser(_) | ScimRoute::PatchUser(_) => {
                        debug!(route = ?route, "SCIM endpoint hit, waiting for body");
                        if let Ok(mut buffer) = self.body_buffer.write() {
                            let key = format!(
                                "scim:{}:{}",
                                route_key(&route),
                                event.metadata.correlation_id
                            );
                            buffer.insert(key, Vec::new());
                        }
                        return AgentResponse::needs_more_data();
                    }
                }
            } else {
                return scim_error_response(404, "SCIM endpoint not found");
            }
        }

        // Check if this is the token exchange endpoint (POST)
        let exchange_config = self.get_exchange_config().unwrap_or_default();
        if exchange_config.enabled
            && request_path == exchange_config.endpoint_path
            && request_method == "POST"
        {
            debug!("Token exchange endpoint hit, waiting for body");

            // Store correlation ID for body buffering
            if let Ok(mut buffer) = self.body_buffer.write() {
                buffer.insert(
                    format!("exchange:{}", event.metadata.correlation_id),
                    Vec::new(),
                );
            }

            return AgentResponse::needs_more_data();
        }

        // Check if this is the SAML ACS endpoint (POST)
        if saml_config.enabled && saml_config.is_acs_path(request_path) && request_method == "POST"
        {
            debug!("SAML ACS endpoint hit, waiting for body");

            // Store correlation ID for body buffering
            if let Ok(mut buffer) = self.body_buffer.write() {
                buffer.insert(event.metadata.correlation_id.clone(), Vec::new());
            }

            // Return needs_more_data to signal we need the request body
            return AgentResponse::needs_more_data();
        }

        // Try mTLS authentication first (highest trust level)
        if let Ok(identity) = self.authenticate_mtls(&event.headers) {
            info!(
                user_id = %identity.id,
                method = %identity.method,
                "mTLS authentication successful"
            );
            self.auth_success_total.fetch_add(1, Ordering::Relaxed);
            return self.build_identity_response(
                identity,
                &user_id_header,
                &auth_method_header,
                &request_method,
                request_path,
            );
        }

        // Try SAML session authentication if enabled
        if saml_config.enabled && saml_config.should_protect_path(request_path) {
            if let Ok(identity) = self.authenticate_saml_session(&event.headers) {
                info!(
                    user_id = %identity.id,
                    method = %identity.method,
                    "SAML session authentication successful"
                );
                self.auth_success_total.fetch_add(1, Ordering::Relaxed);
                return self.build_saml_identity_response(
                    &identity,
                    &saml_config,
                    &user_id_header,
                    &auth_method_header,
                );
            }
        }

        // Try OIDC authentication (Bearer token from OIDC IdP)
        if let Some(auth_header) = event
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "authorization")
            .and_then(|(_, v)| v.first())
        {
            if auth_header.starts_with("Bearer ") || auth_header.starts_with("bearer ") {
                let token = &auth_header[7..];
                if let Ok(identity) = self.authenticate_oidc(token).await {
                    // Check SCIM active status enforcement
                    if scim_config.enabled && scim_config.enforce_active_status {
                        if let Some(ref store) = self.scim_store {
                            // Look up by OIDC subject claim (externalId)
                            if let Ok(Some(false)) =
                                store.is_user_active_by_external_id(&identity.id)
                            {
                                info!(
                                    user_id = %identity.id,
                                    "OIDC auth blocked: SCIM user is deactivated"
                                );
                                self.auth_failure_total.fetch_add(1, Ordering::Relaxed);
                                return AgentResponse::block(
                                    403,
                                    Some("Account deactivated".to_string()),
                                )
                                .with_audit(AuditMetadata {
                                    tags: vec![
                                        "auth".to_string(),
                                        "scim".to_string(),
                                        "deactivated".to_string(),
                                    ],
                                    reason_codes: vec!["SCIM_USER_INACTIVE".to_string()],
                                    ..Default::default()
                                });
                            }
                        }
                    }

                    info!(
                        user_id = %identity.id,
                        method = %identity.method,
                        "OIDC authentication successful"
                    );
                    self.auth_success_total.fetch_add(1, Ordering::Relaxed);
                    return self.build_identity_response(
                        identity,
                        &user_id_header,
                        &auth_method_header,
                        &request_method,
                        request_path,
                    );
                }
            }
        }

        // Try other authentication methods (JWT, API Key, Basic)
        match self.authenticate(&event.headers).await {
            Ok(identity) => {
                info!(
                    user_id = %identity.id,
                    method = %identity.method,
                    "Authentication successful"
                );
                self.auth_success_total.fetch_add(1, Ordering::Relaxed);

                self.build_identity_response(
                    identity,
                    &user_id_header,
                    &auth_method_header,
                    &request_method,
                    request_path,
                )
            }
            Err(e) => {
                debug!("Authentication failed: {}", e);
                self.auth_failure_total.fetch_add(1, Ordering::Relaxed);

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
                    AgentResponse::default_allow().with_audit(AuditMetadata {
                        tags: vec!["auth".to_string(), "fail_open".to_string()],
                        reason_codes: vec!["AUTH_FAILED_OPEN".to_string()],
                        ..Default::default()
                    })
                } else {
                    self.blocked_total.fetch_add(1, Ordering::Relaxed);
                    AgentResponse::block(401, Some("Unauthorized".to_string()))
                        .add_response_header(HeaderOp::Set {
                            name: "WWW-Authenticate".to_string(),
                            value: "Bearer realm=\"zentinel\"".to_string(),
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
        // Check if this is a token exchange request
        let exchange_key = format!("exchange:{}", event.correlation_id);
        let (is_exchange, scim_key) = {
            if let Ok(buffer) = self.body_buffer.read() {
                let is_exchange = buffer.contains_key(&exchange_key);
                // Find SCIM key by suffix match on correlation_id
                let scim_key = buffer
                    .keys()
                    .find(|k| k.starts_with("scim:") && k.ends_with(&event.correlation_id))
                    .cloned();
                (is_exchange, scim_key)
            } else {
                (false, None)
            }
        };

        // Buffer the chunk (data is already a String)
        if let Ok(mut buffer) = self.body_buffer.write() {
            let key = if is_exchange {
                exchange_key.clone()
            } else if let Some(ref sk) = scim_key {
                sk.clone()
            } else {
                event.correlation_id.clone()
            };
            if let Some(body) = buffer.get_mut(&key) {
                body.extend_from_slice(event.data.as_bytes());
            }
        }

        // If this is the last chunk, process the request
        if event.is_last {
            // Handle token exchange
            if is_exchange {
                return self
                    .handle_exchange_body(&event.correlation_id, &exchange_key)
                    .await;
            }

            // Handle SCIM body requests (POST/PUT/PATCH)
            if let Some(ref sk) = scim_key {
                let body_data = {
                    let mut buffer = match self.body_buffer.write() {
                        Ok(b) => b,
                        Err(_) => return scim_error_response(500, "Internal error"),
                    };
                    buffer.remove(sk).unwrap_or_default()
                };

                let route = match parse_scim_buffer_key(sk) {
                    Some(r) => r,
                    None => {
                        return scim_error_response(
                            500,
                            "Failed to parse SCIM route from buffer key",
                        )
                    }
                };

                let scim_store = match &self.scim_store {
                    Some(s) => s,
                    None => return scim_error_response(503, "SCIM store not initialized"),
                };

                let base_url = self
                    .get_scim_config()
                    .map(|c| c.effective_base_url())
                    .unwrap_or_else(|_| "/scim/v2".to_string());

                return handle_scim_body(scim_store, &route, &body_data, &base_url);
            }

            // Handle SAML ACS
            let body_data = {
                let mut buffer = match self.body_buffer.write() {
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
                    return AgentResponse::block(
                        500,
                        Some("Session store not initialized".to_string()),
                    );
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
                    return AgentResponse::block(
                        500,
                        Some("SAML provider not initialized".to_string()),
                    );
                }
            };

            // Process the SAML response
            let assertion = match provider.process_response(&saml_response, session_store) {
                Ok(a) => a,
                Err(e) => {
                    warn!(error = %e, "SAML assertion validation failed");
                    return AgentResponse::block(
                        401,
                        Some("SAML authentication failed".to_string()),
                    )
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
                    tags: vec![
                        "auth".to_string(),
                        "saml".to_string(),
                        "session_created".to_string(),
                    ],
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
        .with_env_filter(format!(
            "{}={},zentinel_agent_protocol=info",
            env!("CARGO_CRATE_NAME"),
            log_level
        ))
        .json()
        .init();

    info!("Starting Zentinel Auth Agent");

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
        .unwrap_or_else(|_| "/var/lib/zentinel-auth/sessions.redb".to_string());

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

    // Initialize SCIM user store
    let scim_store_path = std::env::var("SCIM_STORE_PATH")
        .unwrap_or_else(|_| "/var/lib/sentinel-auth/scim_users.redb".to_string());

    let scim_store = match ScimUserStore::open(PathBuf::from(&scim_store_path)) {
        Ok(store) => {
            info!(path = %scim_store_path, "SCIM user store initialized");
            Some(Arc::new(store))
        }
        Err(e) => {
            warn!(
                error = %e,
                path = %scim_store_path,
                "Failed to initialize SCIM store, SCIM provisioning will be unavailable"
            );
            None
        }
    };

    // Create agent with session store and SCIM store
    let agent = AuthAgent::new(config, session_store, scim_store);

    // Start agent server with appropriate transport
    if let Some(grpc_address) = args.grpc_address {
        // Use gRPC transport
        let addr: std::net::SocketAddr = grpc_address
            .parse()
            .with_context(|| format!("Invalid gRPC address: {}", grpc_address))?;

        info!(
            address = %addr,
            "Starting auth agent with gRPC v2 transport"
        );

        let server = GrpcAgentServerV2::new("zentinel-auth-agent", Box::new(agent));
        server
            .run(addr)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    } else {
        // Use UDS transport (v2 protocol)
        info!(
            socket = ?args.socket,
            "Starting auth agent with UDS v2 transport"
        );

        let server = UdsAgentServerV2::new("zentinel-auth-agent", args.socket, Box::new(agent));
        server.run().await.map_err(|e| anyhow::anyhow!("{}", e))?;
    }

    Ok(())
}

/// The request's path (with query) and upper-cased method.
///
/// Read from the event's `uri` and `method`, which is where Zentinel puts
/// them; the `:path`/`path` and `:method`/`method` headers are only a
/// fallback for senders that leave `uri`/`method` empty.
fn request_target(event: &RequestHeadersEvent) -> (String, String) {
    let header = |names: [&str; 2]| {
        names
            .iter()
            .find_map(|n| event.headers.get(*n).and_then(|v| v.first()))
            .cloned()
    };
    let path = if event.uri.is_empty() {
        header([":path", "path"]).unwrap_or_else(|| "/".to_string())
    } else {
        event.uri.clone()
    };
    let method = if event.method.is_empty() {
        header([":method", "method"]).unwrap_or_default()
    } else {
        event.method.clone()
    };
    (path, method.to_uppercase())
}

/// Convert a ScimRoute to a string key for body buffering.
fn route_key(route: &ScimRoute) -> String {
    match route {
        ScimRoute::CreateUser => "create".to_string(),
        ScimRoute::ReplaceUser(id) => format!("replace:{}", id),
        ScimRoute::PatchUser(id) => format!("patch:{}", id),
        ScimRoute::GetUser(id) => format!("get:{}", id),
        ScimRoute::ListUsers => "list".to_string(),
        ScimRoute::DeleteUser(id) => format!("delete:{}", id),
    }
}

/// Parse a SCIM body buffer key back to a ScimRoute.
fn parse_scim_buffer_key(key: &str) -> Option<ScimRoute> {
    // Key format: "scim:{route_key}:{correlation_id}"
    let rest = key.strip_prefix("scim:")?;
    // Find the last ':' to split route_key from correlation_id
    // route_key can contain ':' (e.g. "replace:uuid"), so we need to handle that
    if rest.starts_with("create:") {
        Some(ScimRoute::CreateUser)
    } else if let Some(rest) = rest.strip_prefix("replace:") {
        // rest is "{id}:{correlation_id}"
        let id = rest.rsplit_once(':')?.0;
        Some(ScimRoute::ReplaceUser(id.to_string()))
    } else if let Some(rest) = rest.strip_prefix("patch:") {
        let id = rest.rsplit_once(':')?.0;
        Some(ScimRoute::PatchUser(id.to_string()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_agent_protocol::{Decision, RequestMetadata};

    fn request_event(
        method: &str,
        uri: &str,
        headers: HashMap<String, Vec<String>>,
    ) -> RequestHeadersEvent {
        RequestHeadersEvent {
            metadata: RequestMetadata {
                correlation_id: "test-correlation".to_string(),
                request_id: "test-request".to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_port: 40000,
                server_name: None,
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: None,
                upstream_id: None,
                timestamp: "2026-10-22T00:00:00Z".to_string(),
                traceparent: None,
            },
            method: method.to_string(),
            uri: uri.to_string(),
            headers,
        }
    }

    fn block_status(response: &AgentResponse) -> Option<u16> {
        match response.decision {
            Decision::Block { status, .. } => Some(status),
            _ => None,
        }
    }

    fn test_config() -> AuthConfig {
        let api_keys = parse_api_keys(["test-key-123:test-api"]);
        let basic_auth_users = parse_basic_auth_users(["testuser:testpass"], true).unwrap();

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

    #[tokio::test]
    async fn test_api_key_auth() {
        let config = test_config();
        let agent = AuthAgent::new(config, None, None);

        let mut headers = HashMap::new();
        headers.insert("X-API-Key".to_string(), vec!["test-key-123".to_string()]);

        let result = agent.authenticate(&headers).await;
        assert!(result.is_ok());

        let identity = result.unwrap();
        assert_eq!(identity.method, AuthMethod::ApiKey);
        assert_eq!(identity.id, "test-api");
    }

    #[tokio::test]
    async fn test_basic_auth() {
        let config = test_config();
        let agent = AuthAgent::new(config, None, None);

        // Base64 encode "testuser:testpass"
        let credentials = BASE64.encode("testuser:testpass");
        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            vec![format!("Basic {}", credentials)],
        );

        let result = agent.authenticate(&headers).await;
        assert!(result.is_ok());

        let identity = result.unwrap();
        assert_eq!(identity.method, AuthMethod::Basic);
        assert_eq!(identity.id, "testuser");
    }

    #[tokio::test]
    async fn test_invalid_api_key() {
        let config = test_config();
        let agent = AuthAgent::new(config, None, None);

        let mut headers = HashMap::new();
        headers.insert("X-API-Key".to_string(), vec!["invalid-key".to_string()]);

        let result = agent.authenticate(&headers).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_no_auth() {
        let config = test_config();
        let agent = AuthAgent::new(config, None, None);

        let mut headers = HashMap::new();
        headers.insert(
            "Content-Type".to_string(),
            vec!["application/json".to_string()],
        );

        let result = agent.authenticate(&headers).await;
        assert!(result.is_err());
    }

    // zentinelproxy/zentinel-agent-auth#6: SAML, mTLS and token exchange do
    // not verify what they trust, and are refused until they do.

    fn refused_configs() -> Vec<(&'static str, serde_json::Value)> {
        vec![
            ("saml", serde_json::json!({ "saml": { "enabled": true } })),
            ("mtls", serde_json::json!({ "mtls": { "enabled": true } })),
            (
                "token-exchange",
                serde_json::json!({ "token-exchange": { "enabled": true } }),
            ),
        ]
    }

    #[tokio::test]
    async fn a_configuration_enabling_an_unverified_module_is_rejected_whole() {
        for (module, mut config) in refused_configs() {
            // Carries a harmless change too, which must not be applied.
            config["api-key-header"] = serde_json::json!("X-Changed");
            let agent = AuthAgent::new(test_config(), None, None);

            assert!(
                !agent.on_configure(config.clone(), None).await,
                "{module}: accepted {config}"
            );

            assert_eq!(
                agent.config.read().unwrap().api_key_header,
                "X-API-Key",
                "{module}: part of a rejected configuration was applied"
            );
            assert!(!agent.get_saml_config().unwrap().enabled, "{module}");
            assert!(!agent.get_mtls_config().unwrap().enabled, "{module}");
            assert!(!agent.get_exchange_config().unwrap().enabled, "{module}");
        }
    }

    #[test]
    fn the_refusal_names_the_module_and_the_issue() {
        for (module, config) in refused_configs() {
            let config: AuthConfigJson = serde_json::from_value(config).unwrap();
            let err = refuse_unverified_modules(&config).unwrap_err().to_string();
            assert!(err.contains(module), "{err}");
            assert!(err.contains("zentinel-agent-auth/issues/6"), "{err}");

            let agent = AuthAgent::new(test_config(), None, None);
            let err = agent.reconfigure(config).unwrap_err().to_string();
            assert!(err.contains(module), "reconfigure: {err}");
        }
    }

    #[test]
    fn enabling_an_unverified_module_directly_is_refused() {
        let agent = AuthAgent::new(test_config(), None, None);
        let saml = SamlConfig {
            enabled: true,
            ..SamlConfig::default()
        };
        assert!(agent.configure_saml(saml).is_err());
        let mtls = MtlsConfig {
            enabled: true,
            ..MtlsConfig::default()
        };
        assert!(agent.configure_mtls(mtls).is_err());
        let exchange = TokenExchangeConfig {
            enabled: true,
            ..TokenExchangeConfig::default()
        };
        assert!(agent.configure_exchange(exchange).is_err());
    }

    #[tokio::test]
    async fn a_configuration_leaving_them_off_is_still_accepted() {
        let agent = AuthAgent::new(test_config(), None, None);
        let config = serde_json::json!({
            "api-key-header": "X-Changed",
            "saml": { "enabled": false },
            "mtls": { "enabled": false },
            "token-exchange": { "enabled": false },
        });
        assert!(agent.on_configure(config, None).await);
        assert_eq!(agent.config.read().unwrap().api_key_header, "X-Changed");
    }

    // OIDC: the token header does not choose the algorithm, unknown kids do
    // not hammer the JWKS endpoint, and configuring never waits for it.

    fn oidc_json(jwks_url: &str) -> serde_json::Value {
        serde_json::json!({
            "oidc": {
                "enabled": true,
                "issuer": oidc::test_support::TEST_ISSUER,
                "jwks-url": jwks_url,
                "jwks-fetch-timeout-ms": 300,
            }
        })
    }

    #[tokio::test]
    async fn configuring_oidc_does_not_wait_for_the_jwks_endpoint() {
        let server = oidc::test_support::JwksServer::start_hanging().await;
        let agent = AuthAgent::new(test_config(), None, None);
        let started = std::time::Instant::now();
        assert!(agent.on_configure(oidc_json(&server.url()), None).await);
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "on_configure waited {:?} for the JWKS endpoint",
            started.elapsed()
        );
        // A token is rejected within the fetch timeout, not after 10 s.
        let token = oidc::test_support::sign_rsa(
            Algorithm::RS256,
            Some(oidc::test_support::TEST_KID),
            &oidc::test_support::test_claims("alice", serde_json::json!({})),
        );
        let started = std::time::Instant::now();
        assert!(agent.authenticate_oidc(&token).await.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn an_oidc_allowlist_naming_hs256_or_none_rejects_the_configuration() {
        for alg in ["HS256", "none"] {
            let agent = AuthAgent::new(test_config(), None, None);
            let mut config = oidc_json("https://issuer.test/jwks.json");
            config["oidc"]["allowed-algorithms"] = serde_json::json!(["RS256", alg]);
            config["api-key-header"] = serde_json::json!("X-Changed");
            assert!(!agent.on_configure(config, None).await, "{alg}");
            assert_eq!(agent.config.read().unwrap().api_key_header, "X-API-Key");
            assert!(!agent.get_oidc_config().unwrap().enabled);
        }
    }

    #[tokio::test]
    async fn an_unknown_kid_flood_through_the_agent_fetches_once() {
        use oidc::test_support::*;
        let server = JwksServer::start().await;
        let agent = AuthAgent::new(test_config(), None, None);
        assert!(agent.on_configure(oidc_json(&server.url()), None).await);

        let good = sign_rsa(
            Algorithm::RS256,
            Some(TEST_KID),
            &test_claims("alice", serde_json::json!({})),
        );
        assert!(agent.authenticate_oidc(&good).await.is_ok());
        let fetches = server.hits();
        assert!(fetches >= 1);

        for i in 0..300 {
            let forged = sign_rsa(
                Algorithm::RS256,
                Some(&format!("unknown-{i}")),
                &test_claims("mallory", serde_json::json!({})),
            );
            assert!(agent.authenticate_oidc(&forged).await.is_err());
        }
        assert_eq!(server.hits(), fetches, "unknown kids refetched the JWKS");
    }

    #[test]
    fn the_request_target_comes_from_the_event_uri_and_method() {
        let event = request_event("get", "/scim/v2/Users?count=1", HashMap::new());
        assert_eq!(
            request_target(&event),
            ("/scim/v2/Users?count=1".to_string(), "GET".to_string())
        );

        let mut headers = HashMap::new();
        headers.insert(":path".to_string(), vec!["/legacy".to_string()]);
        headers.insert(":method".to_string(), vec!["post".to_string()]);
        let event = request_event("", "", headers);
        assert_eq!(
            request_target(&event),
            ("/legacy".to_string(), "POST".to_string())
        );
    }

    #[tokio::test]
    async fn scim_routes_on_the_event_uri() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(ScimUserStore::open(dir.path().join("scim.redb")).unwrap());
        let agent = AuthAgent::new(test_config(), None, Some(store));
        let config = serde_json::json!({
            "scim": { "enabled": true, "bearer-token": "static-scim-token", "use-oidc-auth": false }
        });
        assert!(agent.on_configure(config, None).await);

        let mut headers = HashMap::new();
        headers.insert(
            "authorization".to_string(),
            vec!["Bearer static-scim-token".to_string()],
        );
        // As Zentinel sends it: the path in `uri`, no `:path` header.
        let response = agent
            .on_request_headers(request_event("GET", "/scim/v2/Users", headers))
            .await;
        assert_eq!(block_status(&response), Some(200));
    }

    // SCIM: an OIDC token proves identity, not the right to manage users.

    fn scim_agent_config(jwks_url: &str) -> serde_json::Value {
        let mut config = oidc_json(jwks_url);
        config["scim"] = serde_json::json!({
            "enabled": true,
            "bearer-token": "static-scim-token",
        });
        config
    }

    async fn scim_auth_for(agent: &AuthAgent, header: Option<&str>) -> ScimAuth {
        let scim_config = agent.get_scim_config().unwrap();
        agent.authorize_scim(&scim_config, header).await
    }

    #[tokio::test]
    async fn scim_refuses_an_oidc_token_without_the_scim_scope() {
        use oidc::test_support::*;
        let server = JwksServer::start().await;
        let agent = AuthAgent::new(test_config(), None, None);
        assert!(
            agent
                .on_configure(scim_agent_config(&server.url()), None)
                .await
        );

        let plain_user = sign_rsa(
            Algorithm::RS256,
            Some(TEST_KID),
            &test_claims("alice", serde_json::json!({ "scope": "openid profile" })),
        );
        // The token itself is valid for normal requests...
        assert!(agent.authenticate_oidc(&plain_user).await.is_ok());
        // ...but not for SCIM.
        assert_eq!(
            scim_auth_for(&agent, Some(&format!("Bearer {plain_user}"))).await,
            ScimAuth::MissingScope
        );

        let admin = sign_rsa(
            Algorithm::RS256,
            Some(TEST_KID),
            &test_claims("provisioner", serde_json::json!({ "scope": "openid scim" })),
        );
        assert_eq!(
            scim_auth_for(&agent, Some(&format!("Bearer {admin}"))).await,
            ScimAuth::Allowed
        );

        // Through the request path: 403 for the plain user.
        let mut headers = HashMap::new();
        headers.insert(
            "authorization".to_string(),
            vec![format!("Bearer {plain_user}")],
        );
        let response = agent
            .on_request_headers(request_event("GET", "/scim/v2/Users", headers))
            .await;
        assert_eq!(block_status(&response), Some(403));
    }

    #[tokio::test]
    async fn scim_static_token_is_compared_exactly() {
        let agent = AuthAgent::new(test_config(), None, None);
        assert!(
            agent
                .on_configure(scim_agent_config("https://issuer.test/jwks.json"), None)
                .await
        );
        assert_eq!(
            scim_auth_for(&agent, Some("Bearer static-scim-token")).await,
            ScimAuth::Allowed
        );
        for wrong in [
            "Bearer static-scim-tokeN",
            "Bearer static-scim-token2",
            "Bearer ",
            "static-scim-token",
        ] {
            assert_eq!(
                scim_auth_for(&agent, Some(wrong)).await,
                ScimAuth::Unauthenticated,
                "{wrong}"
            );
        }
        assert_eq!(scim_auth_for(&agent, None).await, ScimAuth::Unauthenticated);
    }

    #[tokio::test]
    async fn scim_with_oidc_and_an_empty_scope_rejects_the_configuration() {
        let agent = AuthAgent::new(test_config(), None, None);
        let mut config = scim_agent_config("https://issuer.test/jwks.json");
        config["scim"]["required-scope"] = serde_json::json!("");
        assert!(!agent.on_configure(config, None).await);
        assert!(!agent.get_scim_config().unwrap().enabled);
        assert!(!agent.get_oidc_config().unwrap().enabled, "partly applied");
    }

    // Cedar: policies see the verified claims, and a policy that does not
    // parse rejects the configuration instead of switching authorization off.

    fn jwt_for(claims: serde_json::Value) -> String {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(b"test-secret-key-at-least-32-chars"),
        )
        .unwrap()
    }

    fn bearer(token: &str) -> HashMap<String, Vec<String>> {
        HashMap::from([("authorization".to_string(), vec![format!("Bearer {token}")])])
    }

    const ROLE_POLICY: &str = r#"
        permit(principal, action == Action::"GET", resource)
        when { resource.path like "/api/*" && context.roles.contains("reader") };
        permit(principal, action, resource)
        when { context.claims has org && context.claims.org == "acme"
               && context.roles.contains("admin") };
    "#;

    #[tokio::test]
    async fn cedar_policies_match_on_jwt_claims_and_roles() {
        let agent = AuthAgent::new(test_config(), None, None);
        let config = serde_json::json!({
            "authz": { "enabled": true, "policy-inline": ROLE_POLICY, "roles-claim": "roles" }
        });
        assert!(agent.on_configure(config, None).await);

        let exp = chrono::Utc::now().timestamp() + 600;
        let reader = jwt_for(serde_json::json!({ "sub": "r", "exp": exp, "roles": ["reader"] }));
        let admin = jwt_for(
            serde_json::json!({ "sub": "a", "exp": exp, "roles": ["admin"], "org": "acme" }),
        );
        let other_org = jwt_for(
            serde_json::json!({ "sub": "o", "exp": exp, "roles": ["admin"], "org": "evil" }),
        );

        let cases = [
            (&reader, "GET", "/api/items", None),
            (&reader, "DELETE", "/api/items", Some(403)),
            (&reader, "GET", "/admin", Some(403)),
            (&admin, "DELETE", "/admin", None),
            (&other_org, "DELETE", "/admin", Some(403)),
        ];
        for (token, method, path, expected) in cases {
            let response = agent
                .on_request_headers(request_event(method, path, bearer(token)))
                .await;
            assert_eq!(block_status(&response), expected, "{method} {path}");
        }
    }

    #[tokio::test]
    async fn cedar_policies_match_on_oidc_array_claims() {
        use oidc::test_support::*;
        let server = JwksServer::start().await;
        let agent = AuthAgent::new(test_config(), None, None);
        let mut config = oidc_json(&server.url());
        config["authz"] = serde_json::json!({
            "enabled": true, "policy-inline": ROLE_POLICY, "roles-claim": "roles"
        });
        assert!(agent.on_configure(config, None).await);

        let token = sign_rsa(
            Algorithm::RS256,
            Some(TEST_KID),
            &test_claims("alice", serde_json::json!({ "roles": ["reader"] })),
        );
        let response = agent
            .on_request_headers(request_event("GET", "/api/items", bearer(&token)))
            .await;
        assert_eq!(block_status(&response), None);
        let response = agent
            .on_request_headers(request_event("POST", "/api/items", bearer(&token)))
            .await;
        assert_eq!(block_status(&response), Some(403));
    }

    #[tokio::test]
    async fn a_cedar_policy_that_does_not_parse_rejects_the_configuration() {
        let agent = AuthAgent::new(test_config(), None, None);
        let config = serde_json::json!({
            "api-key-header": "X-Changed",
            "authz": { "enabled": true, "policy-inline": "permit(principal, action" }
        });
        assert!(!agent.on_configure(config, None).await);
        assert_eq!(agent.config.read().unwrap().api_key_header, "X-API-Key");

        // A later configuration that keeps a broken policy stays rejected,
        // and a working one already in place is kept.
        let good = serde_json::json!({
            "authz": { "enabled": true, "policy-inline": "forbid(principal, action, resource);" }
        });
        assert!(agent.on_configure(good, None).await);
        let broken = serde_json::json!({
            "authz": { "enabled": true, "policy-inline": "this is not cedar" }
        });
        assert!(!agent.on_configure(broken, None).await);
        let mut headers = HashMap::new();
        headers.insert("X-API-Key".to_string(), vec!["test-key-123".to_string()]);
        let response = agent
            .on_request_headers(request_event("GET", "/", headers))
            .await;
        assert_eq!(
            block_status(&response),
            Some(403),
            "the old forbid-all must still apply"
        );

        // Calling configure_authz directly with a broken policy is an error.
        let broken = AuthzConfig {
            enabled: true,
            policy_inline: Some("nope".to_string()),
            ..AuthzConfig::default()
        };
        assert!(agent.configure_authz(broken).is_err());
    }

    // Basic auth: bcrypt hashes, plain text only by opt-in; API keys and
    // passwords compared in constant time.

    // `htpasswd -nbB -C 4 alice s3cret`
    const ALICE_BCRYPT: &str = "$2y$04$fqtNxPl7APYvfBv0y4Wt5.VI.B4ylGv6lyMXZlI6QCa/JVLPn6zAq";

    fn basic(user: &str, pass: &str) -> HashMap<String, Vec<String>> {
        HashMap::from([(
            "authorization".to_string(),
            vec![format!("Basic {}", BASE64.encode(format!("{user}:{pass}")))],
        )])
    }

    #[tokio::test]
    async fn basic_auth_with_a_bcrypt_hash() {
        let agent = AuthAgent::new(test_config(), None, None);
        let config = serde_json::json!({
            "basic-auth-users": [format!("alice:{ALICE_BCRYPT}")]
        });
        assert!(agent.on_configure(config, None).await);

        let ok = agent
            .on_request_headers(request_event("GET", "/", basic("alice", "s3cret")))
            .await;
        assert_eq!(block_status(&ok), None);
        // Again, from the verified cache.
        let ok = agent
            .on_request_headers(request_event("GET", "/", basic("alice", "s3cret")))
            .await;
        assert_eq!(block_status(&ok), None);

        for (user, pass) in [
            ("alice", "wrong"),
            ("alice", ALICE_BCRYPT), // the hash itself is not the password
            ("bob", "s3cret"),
            ("testuser", "testpass"), // replaced by the new user list
        ] {
            let response = agent
                .on_request_headers(request_event("GET", "/", basic(user, pass)))
                .await;
            assert_eq!(block_status(&response), Some(401), "{user}:{pass}");
        }
    }

    #[tokio::test]
    async fn plaintext_basic_auth_passwords_need_an_explicit_opt_in() {
        let agent = AuthAgent::new(test_config(), None, None);
        let config = serde_json::json!({
            "api-key-header": "X-Changed",
            "basic-auth-users": ["alice:s3cret"]
        });
        assert!(!agent.on_configure(config, None).await);
        assert_eq!(agent.config.read().unwrap().api_key_header, "X-API-Key");

        let config = serde_json::json!({
            "basic-auth-users": ["alice:s3cret"],
            "basic-auth-allow-plaintext": true
        });
        assert!(agent.on_configure(config, None).await);
        assert!(agent.authenticate(&basic("alice", "s3cret")).await.is_ok());
        assert!(agent.authenticate(&basic("alice", "s3cre")).await.is_err());
        assert!(agent
            .authenticate(&basic("alice", "s3cret "))
            .await
            .is_err());
    }

    #[test]
    fn plaintext_basic_auth_on_the_command_line_needs_the_flag() {
        let args = Args::parse_from(["zentinel-auth-agent", "--basic-auth-users", "alice:s3cret"]);
        let err = AuthConfig::from_args(&args).err().unwrap();
        assert!(
            err.to_string().contains("basic-auth-allow-plaintext"),
            "{err}"
        );

        let args = Args::parse_from([
            "zentinel-auth-agent",
            "--basic-auth-users",
            "alice:s3cret",
            "--basic-auth-allow-plaintext",
        ]);
        assert!(AuthConfig::from_args(&args).is_ok());

        let hashed = format!("alice:{ALICE_BCRYPT}");
        let args = Args::parse_from(["zentinel-auth-agent", "--basic-auth-users", &hashed]);
        assert!(AuthConfig::from_args(&args).is_ok());
    }

    #[tokio::test]
    async fn api_keys_are_not_kept_in_plain_text_and_must_match_exactly() {
        let config = test_config();
        assert!(!format!("{:?}", config.api_keys).contains("test-key-123"));
        let agent = AuthAgent::new(config, None, None);
        for wrong in ["test-key-12", "test-key-1234", "TEST-KEY-123", ""] {
            let headers = HashMap::from([("X-API-Key".to_string(), vec![wrong.to_string()])]);
            assert!(agent.authenticate(&headers).await.is_err(), "{wrong}");
        }
    }
}
