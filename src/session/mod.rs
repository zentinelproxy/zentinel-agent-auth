//! Session management for SAML authentication.
//!
//! This module provides persistent session storage backed by redb,
//! with in-memory caching and background cleanup.

pub mod cleanup;
pub mod store;
pub mod types;

pub use cleanup::{spawn_cleanup_task, DEFAULT_CLEANUP_INTERVAL_SECS};
pub use store::SessionStore;
pub use types::{Session, SessionId};
