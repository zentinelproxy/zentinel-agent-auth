//! Authorization module using Cedar policy engine.
//!
//! Provides policy-as-code authorization after authentication.

pub mod cedar;
pub mod config;

pub use cedar::CedarAuthorizer;
pub use config::{AuthzConfig, AuthzConfigJson};
