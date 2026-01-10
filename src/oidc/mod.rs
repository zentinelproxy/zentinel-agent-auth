//! OIDC/OAuth 2.0 authentication with JWKS support.
//!
//! Provides token validation using JSON Web Key Sets (JWKS) with automatic
//! key rotation and caching.

pub mod config;
pub mod jwks;
pub mod validator;

pub use config::{OidcConfig, OidcConfigJson};
pub use jwks::JwksCache;
pub use validator::validate_oidc_token;
