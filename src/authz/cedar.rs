//! Cedar policy engine integration.
//!
//! Every request is evaluated with:
//!
//! - principal `User::"<id>"`, an entity with attribute `id`;
//! - action `Action::"<METHOD>"`;
//! - resource `Resource::"<path>"` (query string removed), an entity with
//!   attribute `path`;
//! - context `{ claims, roles, auth_method, method, path, hour }`, where
//!   `claims` holds the verified identity's claims and `roles` the values of
//!   the configured roles claim.
//!
//! The authorizer fails closed: a request it cannot build, or an evaluation
//! in which any policy errors, is denied whatever the default decision.

use anyhow::{anyhow, Context, Result};
use cedar_policy::{
    Authorizer, Context as CedarContext, Decision, Entities, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request,
};
use chrono::Timelike;
use serde_json::{json, Map, Value};
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
    /// Decision when no policy is satisfied (and none errored).
    default_allow: bool,
    /// Claim used as the principal ID, when present.
    principal_claim: String,
    /// Claim holding the roles, if any.
    roles_claim: Option<String>,
    /// Log decisions for debugging.
    log_decisions: bool,
}

/// What is being authorized.
pub struct AuthzRequest<'a> {
    /// Authenticated user ID (used when `principal_claim` is absent).
    pub user_id: &'a str,
    /// How the user authenticated (`jwt`, `oidc`, ...).
    pub auth_method: &'a str,
    /// HTTP method.
    pub method: &'a str,
    /// Request path, possibly with a query string.
    pub path: &'a str,
    /// Verified claims of the identity.
    pub claims: &'a HashMap<String, Value>,
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

impl AuthzDecision {
    fn deny(reason: String) -> Self {
        Self {
            allowed: false,
            reason: Some(reason),
            policy_ids: vec![],
        }
    }
}

impl CedarAuthorizer {
    /// Create a new Cedar authorizer from configuration. Fails if the
    /// configuration is invalid or the policies do not parse.
    pub fn new(config: &AuthzConfig) -> Result<Self> {
        config.validate().map_err(|e| anyhow!(e))?;

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
            principal_claim: config.principal_claim.clone(),
            roles_claim: config.roles_claim.clone(),
            log_decisions: config.log_decisions,
        })
    }

    /// Check if a request is authorized.
    pub fn is_authorized(&self, req: &AuthzRequest<'_>) -> AuthzDecision {
        let principal_id = req
            .claims
            .get(&self.principal_claim)
            .and_then(Value::as_str)
            .unwrap_or(req.user_id);
        let path = req.path.split('?').next().unwrap_or(req.path);

        let (request, entities) = match self.build_request(req, principal_id, path) {
            Ok(built) => built,
            Err(e) => {
                warn!(error = %e, "Failed to build Cedar request, denying");
                return AuthzDecision::deny(format!("Invalid authorization request: {e}"));
            }
        };

        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &entities);

        let policy_ids: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|p| p.to_string())
            .collect();
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();

        let (allowed, reason) = if !errors.is_empty() {
            // An erroring policy is skipped by Cedar, and a skipped `forbid`
            // would let the request through: fail closed instead.
            warn!(
                principal = %principal_id,
                errors = ?errors,
                "Cedar policy evaluation failed, denying"
            );
            (
                false,
                Some(format!("Policy evaluation error: {}", errors.join("; "))),
            )
        } else if response.decision() == Decision::Allow {
            (true, None)
        } else if policy_ids.is_empty() {
            // No policy was satisfied: the configured default applies.
            (
                self.default_allow,
                (!self.default_allow).then(|| "No matching permit policy".to_string()),
            )
        } else {
            (false, Some("Access denied by policy".to_string()))
        };

        if self.log_decisions {
            debug!(
                principal = %principal_id,
                action = %req.method,
                resource = %path,
                allowed = %allowed,
                policies = ?policy_ids,
                "Authorization decision"
            );
        }

        AuthzDecision {
            allowed,
            reason,
            policy_ids,
        }
    }

    fn build_request(
        &self,
        req: &AuthzRequest<'_>,
        principal_id: &str,
        path: &str,
    ) -> Result<(Request, Entities)> {
        let principal = entity_uid("User", principal_id)?;
        let action = entity_uid("Action", req.method)?;
        let resource = entity_uid("Resource", path)?;

        let entities = Entities::from_json_value(
            json!([
                {
                    "uid": { "type": "User", "id": principal_id },
                    "attrs": { "id": principal_id },
                    "parents": []
                },
                {
                    "uid": { "type": "Resource", "id": path },
                    "attrs": { "path": path },
                    "parents": []
                }
            ]),
            None,
        )
        .map_err(|e| anyhow!("entities: {e}"))?;

        let context = CedarContext::from_json_value(
            build_context(
                req,
                path,
                self.roles_claim.as_deref(),
                chrono::Utc::now().hour(),
            ),
            None,
        )
        .map_err(|e| anyhow!("context: {e}"))?;

        let request = Request::new(principal, action, resource, context, None)
            .map_err(|e| anyhow!("request: {e}"))?;
        Ok((request, entities))
    }
}

fn entity_uid(type_name: &str, id: &str) -> Result<EntityUid> {
    let type_name = EntityTypeName::from_str(type_name).map_err(|e| anyhow!("{e}"))?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(id),
    ))
}

/// Build the Cedar context record for a request.
fn build_context(
    req: &AuthzRequest<'_>,
    path: &str,
    roles_claim: Option<&str>,
    hour: u32,
) -> Value {
    let mut claims = Map::new();
    for (k, v) in req.claims {
        if let Some(v) = cedar_value(v) {
            if !k.starts_with("__") {
                claims.insert(k.clone(), v);
            }
        }
    }

    let roles: Vec<Value> = roles_claim
        .and_then(|name| req.claims.get(name))
        .map(roles_from_claim)
        .unwrap_or_default();

    json!({
        "claims": Value::Object(claims),
        "roles": roles,
        "auth_method": req.auth_method,
        "method": req.method,
        "path": path,
        "hour": hour,
    })
}

/// Roles from a claim: an array of strings, or one string of roles separated
/// by spaces or commas.
fn roles_from_claim(value: &Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(|s| Value::String(s.to_string())))
            .collect(),
        Value::String(s) => s
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|r| !r.is_empty())
            .map(|r| Value::String(r.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

/// Convert a JSON claim value to something Cedar's JSON format accepts as a
/// plain value: nulls and non-integer numbers are dropped, and object keys
/// starting with `__` (Cedar's `__entity`/`__extn` escapes) are removed so a
/// claim can never be read as an entity reference or extension value.
fn cedar_value(value: &Value) -> Option<Value> {
    match value {
        Value::Null => None,
        Value::Bool(_) | Value::String(_) => Some(value.clone()),
        Value::Number(n) => n.as_i64().map(Value::from),
        Value::Array(items) => Some(Value::Array(items.iter().filter_map(cedar_value).collect())),
        Value::Object(map) => Some(Value::Object(
            map.iter()
                .filter(|(k, _)| !k.starts_with("__"))
                .filter_map(|(k, v)| cedar_value(v).map(|v| (k.clone(), v)))
                .collect(),
        )),
    }
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
            roles_claim: Some("roles".to_string()),
            log_decisions: true,
        }
    }

    fn check(authz: &CedarAuthorizer, method: &str, path: &str, claims: Value) -> bool {
        let claims: HashMap<String, Value> = serde_json::from_value(claims).unwrap();
        authz
            .is_authorized(&AuthzRequest {
                user_id: "user123",
                auth_method: "jwt",
                method,
                path,
                claims: &claims,
            })
            .allowed
    }

    #[test]
    fn test_permit_all_policy() {
        let config = test_config_with_policy("permit(principal, action, resource);");
        let authz = CedarAuthorizer::new(&config).unwrap();
        assert!(check(&authz, "GET", "/api/users", json!({})));
    }

    #[test]
    fn test_forbid_all_policy() {
        let config = test_config_with_policy("forbid(principal, action, resource);");
        let authz = CedarAuthorizer::new(&config).unwrap();
        assert!(!check(&authz, "GET", "/api/users", json!({})));
    }

    #[test]
    fn test_action_specific_policy() {
        let policy = r#"
            permit(principal, action, resource)
            when { action == Action::"GET" };
        "#;
        let authz = CedarAuthorizer::new(&test_config_with_policy(policy)).unwrap();
        assert!(check(&authz, "GET", "/api/users", json!({})));
        assert!(!check(&authz, "POST", "/api/users", json!({})));
    }

    #[test]
    fn test_invalid_policy() {
        let config = test_config_with_policy("this is not valid cedar");
        assert!(CedarAuthorizer::new(&config).is_err());
    }

    #[test]
    fn roles_and_claims_reach_the_context() {
        let policy = r#"
            permit(principal, action, resource)
            when { context.roles.contains("admin") };
            permit(principal, action == Action::"GET", resource)
            when { context has claims && context.claims has org_id
                   && context.claims.org_id == "acme" };
        "#;
        let authz = CedarAuthorizer::new(&test_config_with_policy(policy)).unwrap();

        assert!(check(
            &authz,
            "DELETE",
            "/x",
            json!({ "roles": ["user", "admin"] })
        ));
        assert!(check(
            &authz,
            "DELETE",
            "/x",
            json!({ "roles": "user admin" })
        ));
        assert!(!check(&authz, "DELETE", "/x", json!({ "roles": ["user"] })));
        assert!(check(&authz, "GET", "/x", json!({ "org_id": "acme" })));
        assert!(!check(&authz, "GET", "/x", json!({ "org_id": "evil" })));
        assert!(!check(&authz, "GET", "/x", json!({})));
    }

    #[test]
    fn principal_and_resource_attributes_are_set() {
        let policy = r#"
            permit(principal, action, resource)
            when { resource.path like "/api/users/*" && principal.id == "alice" };
            permit(principal, action, resource)
            when { context.method == "GET" && context.path == "/health"
                   && context.auth_method == "jwt" };
        "#;
        let authz = CedarAuthorizer::new(&test_config_with_policy(policy)).unwrap();

        // principal-claim `sub` wins over the user ID.
        assert!(check(
            &authz,
            "PUT",
            "/api/users/alice?x=1",
            json!({ "sub": "alice" })
        ));
        assert!(!check(
            &authz,
            "PUT",
            "/api/users/alice",
            json!({ "sub": "bob" })
        ));
        assert!(check(&authz, "GET", "/health", json!({})));
        assert!(!check(&authz, "POST", "/health", json!({})));
    }

    #[test]
    fn a_policy_that_errors_denies() {
        // `context.claims.level` is missing for this user: the forbid errors
        // and Cedar skips it, which without failing closed would let the
        // permit through.
        let policy = r#"
            permit(principal, action, resource);
            forbid(principal, action, resource)
            when { context.claims.level < 3 };
        "#;
        let authz = CedarAuthorizer::new(&test_config_with_policy(policy)).unwrap();
        assert!(!check(&authz, "GET", "/x", json!({})));
        assert!(!check(&authz, "GET", "/x", json!({ "level": 1 })));
        assert!(check(&authz, "GET", "/x", json!({ "level": 5 })));
    }

    #[test]
    fn the_default_decision_applies_only_when_nothing_matched() {
        let policy = r#"
            forbid(principal, action == Action::"DELETE", resource);
        "#;
        let mut config = test_config_with_policy(policy);
        config.default_decision = "allow".to_string();
        let authz = CedarAuthorizer::new(&config).unwrap();
        assert!(check(&authz, "GET", "/x", json!({})));
        assert!(!check(&authz, "DELETE", "/x", json!({})));

        config.default_decision = "deny".to_string();
        let authz = CedarAuthorizer::new(&config).unwrap();
        assert!(!check(&authz, "GET", "/x", json!({})));
    }

    #[test]
    fn hostile_identifiers_and_claims_are_handled() {
        let authz = CedarAuthorizer::new(&test_config_with_policy(
            r#"permit(principal, action, resource) when { principal.id == "a\"b" };"#,
        ))
        .unwrap();
        // Quotes in the principal, a method that is not a token, and claims
        // that look like Cedar escapes or are not representable.
        assert!(check(
            &authz,
            "GE\"T",
            "/p\"ath",
            json!({
                "sub": "a\"b",
                "__entity": { "type": "User", "id": "admin" },
                "nested": { "__extn": { "fn": "ip", "arg": "1.2.3.4" }, "ok": 1 },
                "ratio": 0.5,
                "nothing": null
            })
        ));
    }

    #[test]
    fn every_policy_example_in_the_docs_parses() {
        let doc = include_str!("../../docs/authorization.md");
        let mut blocks = 0;
        for block in doc.split("```cedar").skip(1) {
            let policy = block.split("```").next().unwrap();
            if let Err(e) = PolicySet::from_str(policy) {
                panic!("docs/authorization.md example does not parse: {e}\n{policy}");
            }
            blocks += 1;
        }
        assert!(blocks >= 10, "found only {blocks} cedar blocks");
    }
}
