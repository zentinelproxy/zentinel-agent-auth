//! Cedar policy engine integration.

use anyhow::{anyhow, Context, Result};
use cedar_policy::{Authorizer, Context as CedarContext, Decision, Entities, EntityUid, PolicySet, Request};
use std::collections::HashMap;
use std::str::FromStr;
use tracing::{debug, info, warn};

use super::config::AuthzConfig;

/// Cedar-based authorizer.
pub struct CedarAuthorizer {
    /// Compiled policy set.
    policies: PolicySet,
    /// Cedar authorizer.
    authorizer: Authorizer,
    /// Default decision when no policy matches.
    default_allow: bool,
    /// Log decisions for debugging.
    log_decisions: bool,
}

/// Authorization decision result.
#[derive(Debug)]
pub struct AuthzDecision {
    /// Whether access is allowed.
    pub allowed: bool,
    /// Reason for decision.
    pub reason: Option<String>,
    /// Policy IDs that contributed to decision.
    pub policy_ids: Vec<String>,
}

impl CedarAuthorizer {
    /// Create a new Cedar authorizer from configuration.
    pub fn new(config: &AuthzConfig) -> Result<Self> {
        let policy_text = if let Some(ref path) = config.policy_file {
            std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read policy file: {:?}", path))?
        } else if let Some(ref inline) = config.policy_inline {
            inline.clone()
        } else {
            return Err(anyhow!("No policy provided"));
        };

        let policies = PolicySet::from_str(&policy_text)
            .map_err(|e| anyhow!("Failed to parse Cedar policy: {}", e))?;

        info!(
            policy_count = policies.policies().count(),
            "Cedar authorizer initialized"
        );

        Ok(Self {
            policies,
            authorizer: Authorizer::new(),
            default_allow: config.default_allow(),
            log_decisions: config.log_decisions,
        })
    }

    /// Check if a request is authorized.
    ///
    /// # Arguments
    /// * `principal_id` - User/service identifier (e.g., "user123")
    /// * `action` - HTTP method (e.g., "GET", "POST")
    /// * `resource_path` - Request path (e.g., "/api/users/123")
    /// * `claims` - Additional context from auth (e.g., roles, scopes)
    pub fn is_authorized(
        &self,
        principal_id: &str,
        action: &str,
        resource_path: &str,
        claims: &HashMap<String, String>,
    ) -> AuthzDecision {
        // Build Cedar entities
        let principal = match EntityUid::from_str(&format!("User::\"{}\"", escape_cedar_string(principal_id))) {
            Ok(uid) => uid,
            Err(e) => {
                warn!(error = %e, "Failed to parse principal");
                return AuthzDecision {
                    allowed: self.default_allow,
                    reason: Some(format!("Invalid principal: {}", e)),
                    policy_ids: vec![],
                };
            }
        };

        let action_uid = match EntityUid::from_str(&format!("Action::\"{}\"", action)) {
            Ok(uid) => uid,
            Err(e) => {
                warn!(error = %e, "Failed to parse action");
                return AuthzDecision {
                    allowed: self.default_allow,
                    reason: Some(format!("Invalid action: {}", e)),
                    policy_ids: vec![],
                };
            }
        };

        let resource = match EntityUid::from_str(&format!("Resource::\"{}\"", escape_cedar_string(resource_path))) {
            Ok(uid) => uid,
            Err(e) => {
                warn!(error = %e, "Failed to parse resource");
                return AuthzDecision {
                    allowed: self.default_allow,
                    reason: Some(format!("Invalid resource: {}", e)),
                    policy_ids: vec![],
                };
            }
        };

        // Build context from claims
        let context = build_context(claims);

        // Create request
        let request = match Request::new(
            principal.clone(),
            action_uid.clone(),
            resource.clone(),
            context,
            None, // No schema validation
        ) {
            Ok(req) => req,
            Err(e) => {
                warn!(error = %e, "Failed to create Cedar request");
                return AuthzDecision {
                    allowed: self.default_allow,
                    reason: Some(format!("Invalid request: {}", e)),
                    policy_ids: vec![],
                };
            }
        };

        // Empty entities for now (could be extended to include role hierarchies)
        let entities = Entities::empty();

        // Evaluate
        let response = self.authorizer.is_authorized(&request, &self.policies, &entities);

        let allowed = response.decision() == Decision::Allow;
        let policy_ids: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|p| p.to_string())
            .collect();

        if self.log_decisions {
            debug!(
                principal = %principal_id,
                action = %action,
                resource = %resource_path,
                allowed = %allowed,
                policies = ?policy_ids,
                "Authorization decision"
            );
        }

        AuthzDecision {
            allowed,
            reason: if allowed {
                None
            } else {
                Some("Access denied by policy".to_string())
            },
            policy_ids,
        }
    }

    /// Reload policies from configuration.
    pub fn reload(&mut self, config: &AuthzConfig) -> Result<()> {
        let new_authorizer = Self::new(config)?;
        self.policies = new_authorizer.policies;
        self.default_allow = new_authorizer.default_allow;
        self.log_decisions = new_authorizer.log_decisions;
        info!("Cedar policies reloaded");
        Ok(())
    }
}

/// Build Cedar context from claims map.
fn build_context(claims: &HashMap<String, String>) -> CedarContext {
    // Convert claims to Cedar context
    // For now, create an empty context - claims should be in principal attributes
    // In a more complete implementation, you'd build a proper context record
    CedarContext::empty()
}

/// Escape special characters in Cedar strings.
fn escape_cedar_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config_with_policy(policy: &str) -> AuthzConfig {
        AuthzConfig {
            enabled: true,
            policy_file: None,
            policy_inline: Some(policy.to_string()),
            default_decision: "deny".to_string(),
            principal_claim: "sub".to_string(),
            roles_claim: None,
            log_decisions: true,
        }
    }

    #[test]
    fn test_permit_all_policy() {
        let config = test_config_with_policy("permit(principal, action, resource);");
        let authz = CedarAuthorizer::new(&config).unwrap();

        let decision = authz.is_authorized("user123", "GET", "/api/users", &HashMap::new());
        assert!(decision.allowed);
    }

    #[test]
    fn test_forbid_all_policy() {
        let config = test_config_with_policy("forbid(principal, action, resource);");
        let authz = CedarAuthorizer::new(&config).unwrap();

        let decision = authz.is_authorized("user123", "GET", "/api/users", &HashMap::new());
        assert!(!decision.allowed);
    }

    #[test]
    fn test_action_specific_policy() {
        let policy = r#"
            permit(principal, action, resource)
            when { action == Action::"GET" };
        "#;
        let config = test_config_with_policy(policy);
        let authz = CedarAuthorizer::new(&config).unwrap();

        let get_decision = authz.is_authorized("user123", "GET", "/api/users", &HashMap::new());
        assert!(get_decision.allowed);

        let post_decision = authz.is_authorized("user123", "POST", "/api/users", &HashMap::new());
        assert!(!post_decision.allowed);
    }

    #[test]
    fn test_invalid_policy() {
        let config = test_config_with_policy("this is not valid cedar");
        let result = CedarAuthorizer::new(&config);
        assert!(result.is_err());
    }
}
