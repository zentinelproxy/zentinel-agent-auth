//! SCIM 2.0 Provisioning (RFC 7644).
//!
//! Provides SCIM endpoints for IdP-driven user provisioning.
//! Supports user create, read, update (PUT/PATCH), and delete operations.

pub mod config;
pub mod handler;
pub mod store;
pub mod types;

pub use config::{ScimConfig, ScimConfigJson};
pub use handler::{
    handle_scim_body, handle_scim_delete, handle_scim_get, match_scim_route, scim_error_response,
    ScimRoute,
};
pub use store::ScimUserStore;
