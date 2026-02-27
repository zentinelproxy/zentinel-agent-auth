//! Token Exchange (RFC 8693).
//!
//! Exchange one token type for another. Supports:
//! - SAML assertion → JWT
//! - External JWT → Internal JWT
//! - API Key → Short-lived JWT

pub mod config;
pub mod handler;
pub mod issuer;

pub use config::{TokenExchangeConfig, TokenExchangeConfigJson, TokenType};
pub use handler::{
    parse_exchange_request, SubjectTokenValidator, TokenExchangeResponse, ValidatedSubject,
};
pub use issuer::TokenIssuer;
