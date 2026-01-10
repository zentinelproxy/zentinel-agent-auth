//! Token Exchange (RFC 8693).
//!
//! Exchange one token type for another. Supports:
//! - SAML assertion → JWT
//! - External JWT → Internal JWT
//! - API Key → Short-lived JWT

pub mod config;
pub mod handler;
pub mod issuer;

pub use config::{ExchangeRule, TokenExchangeConfig, TokenExchangeConfigJson, TokenType};
pub use handler::{
    handle_token_exchange, parse_exchange_request, SubjectTokenValidator, TokenExchangeRequest,
    TokenExchangeResponse, ValidatedSubject,
};
pub use issuer::TokenIssuer;
