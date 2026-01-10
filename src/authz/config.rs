//! Authorization configuration.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Authorization configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthzConfig {
    /// Enable authorization.
    #[serde(default)]
    pub enabled: bool,

    /// Path to Cedar policy file (.cedar).
    #[serde(default)]
    pub policy_file: Option<PathBuf>,

    /// Inline Cedar policy (alternative to file).
    #[serde(default)]
    pub policy_inline: Option<String>,

    /// Default decision when no policy matches.
    /// "allow" or "deny" (default: deny)
    #[serde(default = "default_decision")]
    pub default_decision: String,

    /// JWT/identity claim to use as principal ID.
    #[serde(default = "default_principal_claim")]
    pub principal_claim: String,

    /// JWT/identity claim containing roles (optional).
    #[serde(default)]
    pub roles_claim: Option<String>,

    /// Log authorization decisions (for debugging).
    #[serde(default)]
    pub log_decisions: bool,
}

fn default_decision() -> String {
    "deny".to_string()
}

fn default_principal_claim() -> String {
    "sub".to_string()
}

impl Default for AuthzConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            policy_file: None,
            policy_inline: None,
            default_decision: default_decision(),
            principal_claim: default_principal_claim(),
            roles_claim: None,
            log_decisions: false,
        }
    }
}

impl AuthzConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        // Must have either policy file or inline policy
        if self.policy_file.is_none() && self.policy_inline.is_none() {
            return Err("Authorization requires either policy_file or policy_inline".to_string());
        }

        // Validate default decision
        if self.default_decision != "allow" && self.default_decision != "deny" {
            return Err("default_decision must be 'allow' or 'deny'".to_string());
        }

        // If policy file specified, check it exists
        if let Some(ref path) = self.policy_file {
            if !path.exists() {
                return Err(format!("Policy file does not exist: {:?}", path));
            }
        }

        Ok(())
    }

    /// Check if default decision is allow.
    pub fn default_allow(&self) -> bool {
        self.default_decision == "allow"
    }
}

/// JSON configuration for dynamic reconfiguration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct AuthzConfigJson {
    pub enabled: Option<bool>,
    pub policy_file: Option<String>,
    pub policy_inline: Option<String>,
    pub default_decision: Option<String>,
    pub principal_claim: Option<String>,
    pub roles_claim: Option<String>,
    pub log_decisions: Option<bool>,
}

impl AuthzConfigJson {
    /// Apply JSON config to existing config.
    pub fn apply_to(&self, config: &mut AuthzConfig) {
        if let Some(enabled) = self.enabled {
            config.enabled = enabled;
        }
        if let Some(ref path) = self.policy_file {
            config.policy_file = Some(PathBuf::from(path));
        }
        if let Some(ref policy) = self.policy_inline {
            config.policy_inline = Some(policy.clone());
        }
        if let Some(ref decision) = self.default_decision {
            config.default_decision = decision.clone();
        }
        if let Some(ref claim) = self.principal_claim {
            config.principal_claim = claim.clone();
        }
        if let Some(ref claim) = self.roles_claim {
            config.roles_claim = Some(claim.clone());
        }
        if let Some(log) = self.log_decisions {
            config.log_decisions = log;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AuthzConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.default_decision, "deny");
        assert_eq!(config.principal_claim, "sub");
        assert!(!config.default_allow());
    }

    #[test]
    fn test_validation() {
        let mut config = AuthzConfig::default();
        assert!(config.validate().is_ok()); // disabled is valid

        config.enabled = true;
        assert!(config.validate().is_err()); // missing policy

        config.policy_inline = Some("permit(principal, action, resource);".to_string());
        assert!(config.validate().is_ok());

        config.default_decision = "invalid".to_string();
        assert!(config.validate().is_err());
    }
}
