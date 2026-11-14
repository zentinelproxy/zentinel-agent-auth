//! SAML authentication module.
//!
//! Provides SP-initiated SSO with assertion validation and session management.

pub mod config;
pub mod provider;
pub mod verify;

#[cfg(test)]
pub(crate) mod test_support;

pub use config::{SamlConfig, SamlConfigJson};
pub use provider::SamlProvider;
