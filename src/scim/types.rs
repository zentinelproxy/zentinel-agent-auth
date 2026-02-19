//! SCIM 2.0 User resource types (RFC 7643 Section 4.1).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// SCIM User schema URN.
pub const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
/// SCIM List Response schema URN.
pub const SCIM_LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
/// SCIM Error schema URN.
pub const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
/// SCIM Patch Op schema URN.
pub const SCIM_PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/// SCIM User resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    /// Server-assigned UUID.
    pub id: String,
    /// IdP-assigned external identifier (e.g. OIDC sub/oid).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Unique username.
    pub user_name: String,
    /// Name components.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Email addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<ScimEmail>,
    /// Whether the user is active.
    #[serde(default = "default_true")]
    pub active: bool,
    /// Group memberships (read-only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<ScimGroupRef>,
    /// Resource metadata.
    pub meta: ScimMeta,
    /// Schema URNs.
    pub schemas: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl ScimUser {
    /// Create a new SCIM user with server-assigned ID and metadata.
    pub fn new(user_name: String, external_id: Option<String>, base_url: &str) -> Self {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        Self {
            id: id.clone(),
            external_id,
            user_name,
            name: None,
            display_name: None,
            emails: Vec::new(),
            active: true,
            groups: Vec::new(),
            meta: ScimMeta {
                resource_type: "User".to_string(),
                created: now,
                last_modified: now,
                location: format!("{}/Users/{}", base_url.trim_end_matches('/'), id),
                version: None,
            },
            schemas: vec![SCIM_USER_SCHEMA.to_string()],
        }
    }

    /// Update the meta.location URL (e.g. after config change).
    pub fn update_location(&mut self, base_url: &str) {
        self.meta.location = format!("{}/Users/{}", base_url.trim_end_matches('/'), self.id);
    }
}

/// SCIM Name sub-attribute.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honorific_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honorific_suffix: Option<String>,
}

/// SCIM Email sub-attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimEmail {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default)]
    pub primary: bool,
}

/// SCIM Group reference (read-only on User resource).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroupRef {
    pub value: String,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// SCIM resource metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimMeta {
    pub resource_type: String,
    pub created: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// SCIM List Response (RFC 7644 Section 3.4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimListResponse {
    pub schemas: Vec<String>,
    pub total_results: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items_per_page: Option<usize>,
    #[serde(rename = "Resources")]
    pub resources: Vec<ScimUser>,
}

impl ScimListResponse {
    pub fn new(resources: Vec<ScimUser>, total_results: usize, start_index: usize, items_per_page: usize) -> Self {
        Self {
            schemas: vec![SCIM_LIST_SCHEMA.to_string()],
            total_results,
            start_index: Some(start_index),
            items_per_page: Some(items_per_page),
            resources,
        }
    }
}

/// SCIM Error response (RFC 7644 Section 3.12).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimError {
    pub schemas: Vec<String>,
    pub detail: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
}

impl ScimError {
    pub fn new(status: u16, detail: impl Into<String>) -> Self {
        Self {
            schemas: vec![SCIM_ERROR_SCHEMA.to_string()],
            detail: detail.into(),
            status: status.to_string(),
            scim_type: None,
        }
    }

    pub fn with_type(mut self, scim_type: impl Into<String>) -> Self {
        self.scim_type = Some(scim_type.into());
        self
    }

    pub fn uniqueness(detail: impl Into<String>) -> Self {
        Self::new(409, detail).with_type("uniqueness")
    }

    #[allow(dead_code)]
    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(404, detail)
    }

    #[allow(dead_code)]
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(400, detail)
    }
}

/// SCIM Patch request (RFC 7644 Section 3.5.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimPatchRequest {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<PatchOperation>,
}

/// SCIM Patch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchOperation {
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// Input type for creating a SCIM user (subset of ScimUser without server-assigned fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUserInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub emails: Vec<ScimEmail>,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default)]
    pub schemas: Vec<String>,
    /// Password is accepted but never stored or returned (SCIM convention).
    #[serde(skip_serializing)]
    #[allow(dead_code)]
    pub password: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scim_user_new() {
        let user = ScimUser::new("jdoe".to_string(), Some("ext-123".to_string()), "https://example.com/scim/v2");
        assert_eq!(user.user_name, "jdoe");
        assert_eq!(user.external_id, Some("ext-123".to_string()));
        assert!(user.active);
        assert_eq!(user.schemas, vec![SCIM_USER_SCHEMA]);
        assert!(user.meta.location.starts_with("https://example.com/scim/v2/Users/"));
        assert_eq!(user.meta.resource_type, "User");
    }

    #[test]
    fn test_scim_user_serialization_roundtrip() {
        let user = ScimUser::new("jdoe".to_string(), None, "https://example.com/scim/v2");
        let json = serde_json::to_string(&user).unwrap();
        let parsed: ScimUser = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.user_name, "jdoe");
        assert_eq!(parsed.id, user.id);
        assert!(parsed.active);
    }

    #[test]
    fn test_password_not_serialized() {
        let input = ScimUserInput {
            external_id: None,
            user_name: "jdoe".to_string(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
            schemas: vec![],
            password: Some("secret".to_string()),
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(!json.contains("secret"));
        assert!(!json.contains("password"));
    }

    #[test]
    fn test_list_response_format() {
        let users = vec![
            ScimUser::new("alice".to_string(), None, "https://example.com/scim/v2"),
            ScimUser::new("bob".to_string(), None, "https://example.com/scim/v2"),
        ];
        let response = ScimListResponse::new(users, 2, 1, 100);
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("ListResponse"));
        assert!(json.contains("\"totalResults\":2"));
        assert!(json.contains("\"Resources\""));
    }

    #[test]
    fn test_error_format() {
        let err = ScimError::uniqueness("userName already exists");
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"status\":\"409\""));
        assert!(json.contains("uniqueness"));
        assert!(json.contains("userName already exists"));
    }

    #[test]
    fn test_patch_request_deserialization() {
        let json = r#"{
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "replace", "path": "active", "value": false},
                {"op": "add", "path": "name.givenName", "value": "Jane"}
            ]
        }"#;
        let patch: ScimPatchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(patch.operations.len(), 2);
        assert_eq!(patch.operations[0].op, "replace");
        assert_eq!(patch.operations[0].path.as_deref(), Some("active"));
    }

    #[test]
    fn test_scim_email_serialization() {
        let email = ScimEmail {
            value: "user@example.com".to_string(),
            r#type: Some("work".to_string()),
            primary: true,
        };
        let json = serde_json::to_string(&email).unwrap();
        assert!(json.contains("user@example.com"));
        assert!(json.contains("\"type\":\"work\""));
        assert!(json.contains("\"primary\":true"));
    }
}
