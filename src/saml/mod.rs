//! SAML authentication module.
//!
//! Provides SP-initiated SSO with assertion validation and session management.

pub mod config;
pub mod provider;

pub use config::{SamlConfig, SamlConfigJson};
pub use provider::{ProcessedAssertion, SamlProvider};
