//! SCIM 2.0 provisioning configuration.

use serde::{Deserialize, Serialize};

/// SCIM provisioning configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimConfig {
    /// Enable SCIM provisioning endpoint.
    #[serde(default)]
    pub enabled: bool,

    /// Base path for SCIM endpoints.
    #[serde(default = "default_base_path")]
    pub base_path: String,

    /// Static bearer token for SCIM endpoint authentication.
    /// If set, requests must include `Authorization: Bearer <token>`.
    #[serde(default)]
    pub bearer_token: Option<String>,

    /// Use OIDC token validation for SCIM endpoint authentication.
    /// Reuses the existing OIDC validator configured on the agent.
    #[serde(default = "default_true")]
    pub use_oidc_auth: bool,

    /// OAuth scope an OIDC token must carry to use the SCIM endpoint.
    /// Defaults to `scim`; it cannot be empty while `use_oidc_auth` is on,
    /// because any user who can log in would otherwise manage users.
    #[serde(default = "default_required_scope")]
    pub required_scope: Option<String>,

    /// Path to the SCIM user store (redb database file).
    #[serde(default = "default_store_path")]
    pub store_path: String,

    /// Enforce SCIM `active` status during OIDC authentication.
    /// When true, users with `active: false` will be rejected.
    #[serde(default = "default_true")]
    pub enforce_active_status: bool,

    /// Base URL for generating meta.location URLs.
    /// If not set, location URLs will use the base_path.
    #[serde(default)]
    pub location_base_url: Option<String>,
}

fn default_base_path() -> String {
    "/scim/v2".to_string()
}

fn default_store_path() -> String {
    "/var/lib/sentinel-auth/scim_users.redb".to_string()
}

/// Scope an OIDC token needs for SCIM unless configured otherwise.
pub const DEFAULT_SCIM_SCOPE: &str = "scim";

fn default_required_scope() -> Option<String> {
    Some(DEFAULT_SCIM_SCOPE.to_string())
}

fn default_true() -> bool {
    true
}

impl Default for ScimConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_path: default_base_path(),
            bearer_token: None,
            use_oidc_auth: true,
            required_scope: default_required_scope(),
            store_path: default_store_path(),
            enforce_active_status: true,
            location_base_url: None,
        }
    }
}

impl ScimConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        // Must have at least one auth method
        if self.bearer_token.is_none() && !self.use_oidc_auth {
            return Err(
                "SCIM requires either bearer_token or use_oidc_auth to be configured".to_string(),
            );
        }

        // OIDC tokens prove who the caller is, not that they may administer
        // users: without a scope, every user of the IdP could.
        if self.use_oidc_auth && self.oidc_scope().is_none() {
            return Err(
                "SCIM use_oidc_auth requires a non-empty required_scope (default \"scim\")"
                    .to_string(),
            );
        }

        // Base path must start with /
        if !self.base_path.starts_with('/') {
            return Err(format!(
                "SCIM base_path must start with '/': {}",
                self.base_path
            ));
        }

        // Store path must not be empty
        if self.store_path.is_empty() {
            return Err("SCIM store_path must not be empty".to_string());
        }

        Ok(())
    }

    /// The scope an OIDC token needs, if a non-empty one is configured.
    pub fn oidc_scope(&self) -> Option<&str> {
        self.required_scope
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    /// Get the effective base URL for meta.location generation.
    pub fn effective_base_url(&self) -> String {
        self.location_base_url
            .clone()
            .unwrap_or_else(|| self.base_path.clone())
    }

    /// Check if a request path matches the SCIM base path.
    pub fn matches_path(&self, path: &str) -> bool {
        // Strip query string for matching
        let path = path.split('?').next().unwrap_or(path);
        let base = self.base_path.trim_end_matches('/');
        path == base || path.starts_with(&format!("{}/", base))
    }
}

/// JSON configuration for dynamic reconfiguration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ScimConfigJson {
    pub enabled: Option<bool>,
    pub base_path: Option<String>,
    pub bearer_token: Option<String>,
    pub use_oidc_auth: Option<bool>,
    pub required_scope: Option<String>,
    pub store_path: Option<String>,
    pub enforce_active_status: Option<bool>,
    pub location_base_url: Option<String>,
}

impl ScimConfigJson {
    /// Apply JSON config to existing config.
    pub fn apply_to(&self, config: &mut ScimConfig) {
        if let Some(enabled) = self.enabled {
            config.enabled = enabled;
        }
        if let Some(ref path) = self.base_path {
            config.base_path = path.clone();
        }
        if let Some(ref token) = self.bearer_token {
            config.bearer_token = Some(token.clone());
        }
        if let Some(use_oidc) = self.use_oidc_auth {
            config.use_oidc_auth = use_oidc;
        }
        if let Some(ref scope) = self.required_scope {
            config.required_scope = Some(scope.clone());
        }
        if let Some(ref path) = self.store_path {
            config.store_path = path.clone();
        }
        if let Some(enforce) = self.enforce_active_status {
            config.enforce_active_status = enforce;
        }
        if let Some(ref url) = self.location_base_url {
            config.location_base_url = Some(url.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ScimConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.base_path, "/scim/v2");
        assert!(config.use_oidc_auth);
        assert!(config.enforce_active_status);
        assert_eq!(config.store_path, "/var/lib/sentinel-auth/scim_users.redb");
        assert_eq!(config.oidc_scope(), Some(DEFAULT_SCIM_SCOPE));
    }

    #[test]
    fn oidc_auth_without_a_scope_is_rejected() {
        for scope in [None, Some(String::new()), Some("  ".to_string())] {
            let config = ScimConfig {
                enabled: true,
                use_oidc_auth: true,
                required_scope: scope.clone(),
                ..Default::default()
            };
            assert!(config.validate().is_err(), "{scope:?}");
        }
        // Static-token-only SCIM does not need a scope.
        let config = ScimConfig {
            enabled: true,
            use_oidc_auth: false,
            bearer_token: Some("t".to_string()),
            required_scope: None,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_disabled() {
        let config = ScimConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_no_auth() {
        let config = ScimConfig {
            enabled: true,
            bearer_token: None,
            use_oidc_auth: false,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_with_bearer() {
        let config = ScimConfig {
            enabled: true,
            bearer_token: Some("test-token".to_string()),
            use_oidc_auth: false,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_with_oidc() {
        let config = ScimConfig {
            enabled: true,
            bearer_token: None,
            use_oidc_auth: true,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_bad_base_path() {
        let config = ScimConfig {
            enabled: true,
            base_path: "no-leading-slash".to_string(),
            bearer_token: Some("token".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_matches_path() {
        let config = ScimConfig::default();
        assert!(config.matches_path("/scim/v2"));
        assert!(config.matches_path("/scim/v2/Users"));
        assert!(config.matches_path("/scim/v2/Users/123"));
        assert!(config.matches_path("/scim/v2/Users?filter=userName+eq+%22test%22"));
        assert!(!config.matches_path("/api/users"));
        assert!(!config.matches_path("/scim/v1"));
    }

    #[test]
    fn test_json_apply() {
        let mut config = ScimConfig::default();
        let json = ScimConfigJson {
            enabled: Some(true),
            bearer_token: Some("my-token".to_string()),
            base_path: Some("/scim".to_string()),
            ..Default::default()
        };
        json.apply_to(&mut config);
        assert!(config.enabled);
        assert_eq!(config.bearer_token, Some("my-token".to_string()));
        assert_eq!(config.base_path, "/scim");
        // Unchanged fields
        assert!(config.use_oidc_auth);
        assert!(config.enforce_active_status);
    }

    #[test]
    fn test_effective_base_url() {
        let mut config = ScimConfig::default();
        assert_eq!(config.effective_base_url(), "/scim/v2");

        config.location_base_url = Some("https://auth.example.com/scim/v2".to_string());
        assert_eq!(
            config.effective_base_url(),
            "https://auth.example.com/scim/v2"
        );
    }
}
