//! SCIM 2.0 request routing and handling (RFC 7644).

use zentinel_agent_protocol::{AgentResponse, AuditMetadata, HeaderOp};
use tracing::{info, warn};

use super::store::ScimUserStore;
use super::types::{
    PatchOperation, ScimError, ScimListResponse, ScimPatchRequest, ScimUser, ScimUserInput,
    SCIM_PATCH_OP_SCHEMA,
};

/// Matched SCIM route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScimRoute {
    /// POST /Users
    CreateUser,
    /// GET /Users/{id}
    GetUser(String),
    /// GET /Users
    ListUsers,
    /// PUT /Users/{id}
    ReplaceUser(String),
    /// PATCH /Users/{id}
    PatchUser(String),
    /// DELETE /Users/{id}
    DeleteUser(String),
}

/// Match a request path + method to a SCIM route.
/// `base_path` is the configured SCIM base (e.g. "/scim/v2").
/// `path` is the full request path (may include query string).
/// `method` is the HTTP method (uppercase).
pub fn match_scim_route(base_path: &str, path: &str, method: &str) -> Option<ScimRoute> {
    // Strip query string
    let path = path.split('?').next().unwrap_or(path);
    let base = base_path.trim_end_matches('/');

    // Strip base path to get relative path
    let relative = if path == base {
        ""
    } else {
        path.strip_prefix(&format!("{}/", base))?
    };

    match (method, relative) {
        ("POST", "Users") => Some(ScimRoute::CreateUser),
        ("GET", "Users") => Some(ScimRoute::ListUsers),
        ("GET", rel) if rel.starts_with("Users/") => {
            let id = rel.strip_prefix("Users/")?;
            if id.is_empty() {
                None
            } else {
                Some(ScimRoute::GetUser(id.to_string()))
            }
        }
        ("PUT", rel) if rel.starts_with("Users/") => {
            let id = rel.strip_prefix("Users/")?;
            if id.is_empty() {
                None
            } else {
                Some(ScimRoute::ReplaceUser(id.to_string()))
            }
        }
        ("PATCH", rel) if rel.starts_with("Users/") => {
            let id = rel.strip_prefix("Users/")?;
            if id.is_empty() {
                None
            } else {
                Some(ScimRoute::PatchUser(id.to_string()))
            }
        }
        ("DELETE", rel) if rel.starts_with("Users/") => {
            let id = rel.strip_prefix("Users/")?;
            if id.is_empty() {
                None
            } else {
                Some(ScimRoute::DeleteUser(id.to_string()))
            }
        }
        _ => None,
    }
}

/// Handle a SCIM GET request (GetUser or ListUsers).
pub fn handle_scim_get(
    store: &ScimUserStore,
    route: &ScimRoute,
    query_string: Option<&str>,
    _base_url: &str,
) -> AgentResponse {
    match route {
        ScimRoute::GetUser(id) => {
            match store.get(id) {
                Ok(Some(user)) => scim_response(200, &user),
                Ok(None) => scim_error_response(404, &format!("User '{}' not found", id)),
                Err(e) => {
                    warn!(error = %e, "SCIM get user error");
                    scim_error_response(500, "Internal server error")
                }
            }
        }
        ScimRoute::ListUsers => {
            // Parse query parameters
            let (start_index, count, filter) = parse_query_params(query_string);

            // Handle filter
            if let Some(ref filter_str) = filter {
                match parse_filter(filter_str) {
                    Ok((field, value)) => {
                        let result = match field.as_str() {
                            "externalId" => store.get_by_external_id(&value),
                            "userName" => store.get_by_username(&value),
                            _ => return scim_error_response(400, &format!(
                                "Unsupported filter field: '{}'. Only 'externalId' and 'userName' are supported", field
                            )),
                        };
                        match result {
                            Ok(Some(user)) => {
                                let response = ScimListResponse::new(vec![user], 1, 1, 1);
                                scim_response(200, &response)
                            }
                            Ok(None) => {
                                let response = ScimListResponse::new(vec![], 0, 1, 0);
                                scim_response(200, &response)
                            }
                            Err(e) => {
                                warn!(error = %e, "SCIM filter error");
                                scim_error_response(500, "Internal server error")
                            }
                        }
                    }
                    Err(msg) => scim_error_response(400, &msg),
                }
            } else {
                match store.list(start_index, count) {
                    Ok((users, total)) => {
                        let response = ScimListResponse::new(users, total, start_index, count);
                        scim_response(200, &response)
                    }
                    Err(e) => {
                        warn!(error = %e, "SCIM list error");
                        scim_error_response(500, "Internal server error")
                    }
                }
            }
        }
        _ => scim_error_response(405, "Method not allowed"),
    }
}

/// Handle a SCIM request that has a body (Create, Replace, Patch).
pub fn handle_scim_body(
    store: &ScimUserStore,
    route: &ScimRoute,
    body: &[u8],
    base_url: &str,
) -> AgentResponse {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return scim_error_response(400, "Invalid UTF-8 in request body"),
    };

    match route {
        ScimRoute::CreateUser => handle_create(store, body_str, base_url),
        ScimRoute::ReplaceUser(id) => handle_replace(store, id, body_str, base_url),
        ScimRoute::PatchUser(id) => handle_patch(store, id, body_str),
        _ => scim_error_response(405, "Method not allowed"),
    }
}

/// Handle a SCIM DELETE request.
pub fn handle_scim_delete(store: &ScimUserStore, id: &str) -> AgentResponse {
    match store.delete(id) {
        Ok(true) => {
            info!(user_id = %id, "SCIM user deleted (deactivated)");
            AgentResponse::block(204, None)
                .add_response_header(HeaderOp::Set {
                    name: "Content-Type".to_string(),
                    value: "application/scim+json".to_string(),
                })
                .with_audit(AuditMetadata {
                    tags: vec!["scim".to_string(), "delete".to_string()],
                    ..Default::default()
                })
        }
        Ok(false) => scim_error_response(404, &format!("User '{}' not found", id)),
        Err(e) => {
            warn!(error = %e, "SCIM delete error");
            scim_error_response(500, "Internal server error")
        }
    }
}

fn handle_create(store: &ScimUserStore, body: &str, base_url: &str) -> AgentResponse {
    let input: ScimUserInput = match serde_json::from_str(body) {
        Ok(i) => i,
        Err(e) => return scim_error_response(400, &format!("Invalid request body: {}", e)),
    };

    let mut user = ScimUser::new(input.user_name, input.external_id, base_url);
    user.name = input.name;
    user.display_name = input.display_name;
    user.emails = input.emails;
    user.active = input.active;

    match store.create(user) {
        Ok(created) => {
            info!(user_id = %created.id, user_name = %created.user_name, "SCIM user created");

            let location = created.meta.location.clone();
            match serde_json::to_string(&created) {
                Ok(json) => {
                    AgentResponse::block(201, Some(json))
                        .add_response_header(HeaderOp::Set {
                            name: "Content-Type".to_string(),
                            value: "application/scim+json".to_string(),
                        })
                        .add_response_header(HeaderOp::Set {
                            name: "Location".to_string(),
                            value: location,
                        })
                        .with_audit(AuditMetadata {
                            tags: vec!["scim".to_string(), "create".to_string()],
                            ..Default::default()
                        })
                }
                Err(_) => scim_error_response(500, "Failed to serialize response"),
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("already exists") {
                let err = ScimError::uniqueness(&msg);
                match serde_json::to_string(&err) {
                    Ok(json) => {
                        AgentResponse::block(409, Some(json))
                            .add_response_header(HeaderOp::Set {
                                name: "Content-Type".to_string(),
                                value: "application/scim+json".to_string(),
                            })
                            .with_audit(AuditMetadata {
                                tags: vec!["scim".to_string(), "create".to_string(), "conflict".to_string()],
                                ..Default::default()
                            })
                    }
                    Err(_) => scim_error_response(409, &msg),
                }
            } else {
                warn!(error = %e, "SCIM create error");
                scim_error_response(500, "Internal server error")
            }
        }
    }
}

fn handle_replace(store: &ScimUserStore, id: &str, body: &str, base_url: &str) -> AgentResponse {
    let input: ScimUserInput = match serde_json::from_str(body) {
        Ok(i) => i,
        Err(e) => return scim_error_response(400, &format!("Invalid request body: {}", e)),
    };

    // Build a full user from input, preserving the existing ID
    let mut user = ScimUser::new(input.user_name, input.external_id, base_url);
    user.id = id.to_string();
    user.name = input.name;
    user.display_name = input.display_name;
    user.emails = input.emails;
    user.active = input.active;
    user.update_location(base_url);

    match store.replace(id, user) {
        Ok(replaced) => {
            info!(user_id = %replaced.id, user_name = %replaced.user_name, "SCIM user replaced");
            scim_response(200, &replaced)
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") {
                scim_error_response(404, &msg)
            } else if msg.contains("already exists") {
                let err = ScimError::uniqueness(&msg);
                match serde_json::to_string(&err) {
                    Ok(json) => {
                        AgentResponse::block(409, Some(json))
                            .add_response_header(HeaderOp::Set {
                                name: "Content-Type".to_string(),
                                value: "application/scim+json".to_string(),
                            })
                    }
                    Err(_) => scim_error_response(409, &msg),
                }
            } else {
                warn!(error = %e, "SCIM replace error");
                scim_error_response(500, "Internal server error")
            }
        }
    }
}

fn handle_patch(store: &ScimUserStore, id: &str, body: &str) -> AgentResponse {
    let patch_req: ScimPatchRequest = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return scim_error_response(400, &format!("Invalid patch request: {}", e)),
    };

    // Validate schema
    if !patch_req.schemas.contains(&SCIM_PATCH_OP_SCHEMA.to_string()) {
        return scim_error_response(400, "Missing PatchOp schema in request");
    }

    // Get existing user
    let mut user = match store.get(id) {
        Ok(Some(u)) => u,
        Ok(None) => return scim_error_response(404, &format!("User '{}' not found", id)),
        Err(e) => {
            warn!(error = %e, "SCIM patch get error");
            return scim_error_response(500, "Internal server error");
        }
    };

    // Apply operations
    for op in &patch_req.operations {
        if let Err(msg) = apply_patch_op(&mut user, op) {
            return scim_error_response(400, &msg);
        }
    }

    // Save
    match store.replace(id, user) {
        Ok(updated) => {
            info!(user_id = %updated.id, "SCIM user patched");
            scim_response(200, &updated)
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("already exists") {
                let err = ScimError::uniqueness(&msg);
                match serde_json::to_string(&err) {
                    Ok(json) => {
                        AgentResponse::block(409, Some(json))
                            .add_response_header(HeaderOp::Set {
                                name: "Content-Type".to_string(),
                                value: "application/scim+json".to_string(),
                            })
                    }
                    Err(_) => scim_error_response(409, &msg),
                }
            } else {
                warn!(error = %e, "SCIM patch save error");
                scim_error_response(500, "Internal server error")
            }
        }
    }
}

/// Apply a single PATCH operation to a ScimUser.
fn apply_patch_op(user: &mut ScimUser, op: &PatchOperation) -> Result<(), String> {
    let op_type = op.op.to_lowercase();
    match op_type.as_str() {
        "replace" | "add" => {
            let path = op.path.as_deref().unwrap_or("");
            let value = op.value.as_ref()
                .ok_or_else(|| format!("{} operation requires a value", op_type))?;

            match path {
                "userName" => {
                    user.user_name = value.as_str()
                        .ok_or("userName must be a string")?
                        .to_string();
                }
                "displayName" => {
                    user.display_name = Some(
                        value.as_str()
                            .ok_or("displayName must be a string")?
                            .to_string(),
                    );
                }
                "active" => {
                    user.active = value.as_bool()
                        .ok_or("active must be a boolean")?;
                }
                "externalId" => {
                    user.external_id = Some(
                        value.as_str()
                            .ok_or("externalId must be a string")?
                            .to_string(),
                    );
                }
                "name.givenName" => {
                    let name = user.name.get_or_insert_with(Default::default);
                    name.given_name = Some(
                        value.as_str()
                            .ok_or("name.givenName must be a string")?
                            .to_string(),
                    );
                }
                "name.familyName" => {
                    let name = user.name.get_or_insert_with(Default::default);
                    name.family_name = Some(
                        value.as_str()
                            .ok_or("name.familyName must be a string")?
                            .to_string(),
                    );
                }
                "name.formatted" => {
                    let name = user.name.get_or_insert_with(Default::default);
                    name.formatted = Some(
                        value.as_str()
                            .ok_or("name.formatted must be a string")?
                            .to_string(),
                    );
                }
                "emails" => {
                    let emails: Vec<super::types::ScimEmail> = serde_json::from_value(value.clone())
                        .map_err(|e| format!("Invalid emails value: {}", e))?;
                    user.emails = emails;
                }
                "" => {
                    // No path: value must be an object with fields to set
                    if let Some(obj) = value.as_object() {
                        for (key, val) in obj {
                            let sub_op = PatchOperation {
                                op: op.op.clone(),
                                path: Some(key.clone()),
                                value: Some(val.clone()),
                            };
                            apply_patch_op(user, &sub_op)?;
                        }
                    } else {
                        return Err("Value must be an object when path is not specified".to_string());
                    }
                }
                other => {
                    return Err(format!("Unsupported patch path: '{}'", other));
                }
            }
        }
        "remove" => {
            let path = op.path.as_deref()
                .ok_or("remove operation requires a path")?;

            match path {
                "displayName" => user.display_name = None,
                "externalId" => user.external_id = None,
                "name.givenName" => {
                    if let Some(ref mut name) = user.name {
                        name.given_name = None;
                    }
                }
                "name.familyName" => {
                    if let Some(ref mut name) = user.name {
                        name.family_name = None;
                    }
                }
                "name.formatted" => {
                    if let Some(ref mut name) = user.name {
                        name.formatted = None;
                    }
                }
                "name" => user.name = None,
                "emails" => user.emails.clear(),
                other => {
                    return Err(format!("Unsupported remove path: '{}'", other));
                }
            }
        }
        _ => return Err(format!("Unsupported patch operation: '{}'", op_type)),
    }

    Ok(())
}

/// Parse query parameters from a query string.
fn parse_query_params(query: Option<&str>) -> (usize, usize, Option<String>) {
    let mut start_index = 1usize;
    let mut count = 100usize;
    let mut filter = None;

    if let Some(qs) = query {
        for pair in qs.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                match key {
                    "startIndex" => {
                        if let Ok(v) = value.parse::<usize>() {
                            start_index = v.max(1);
                        }
                    }
                    "count" => {
                        if let Ok(v) = value.parse::<usize>() {
                            count = v.min(1000);
                        }
                    }
                    "filter" => {
                        // URL-decode the filter value
                        filter = Some(
                            urlencoding::decode(value)
                                .map(|s| s.into_owned())
                                .unwrap_or_else(|_| value.to_string()),
                        );
                    }
                    _ => {}
                }
            }
        }
    }

    (start_index, count, filter)
}

/// Parse a simple SCIM filter (only `field eq "value"` supported).
fn parse_filter(filter_str: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = filter_str.splitn(3, ' ').collect();
    if parts.len() != 3 {
        return Err(format!(
            "Invalid filter syntax: '{}'. Expected: field eq \"value\"",
            filter_str
        ));
    }

    let field = parts[0];
    let operator = parts[1];
    let value = parts[2];

    if operator != "eq" {
        return Err(format!(
            "Unsupported filter operator: '{}'. Only 'eq' is supported",
            operator
        ));
    }

    // Strip surrounding quotes
    let value = value.trim_matches('"');
    if value.is_empty() {
        return Err("Filter value must not be empty".to_string());
    }

    match field {
        "externalId" | "userName" => Ok((field.to_string(), value.to_string())),
        _ => Err(format!(
            "Unsupported filter field: '{}'. Only 'externalId' and 'userName' are supported",
            field
        )),
    }
}

/// Build a SCIM JSON response with proper content type.
pub fn scim_response<T: serde::Serialize>(status: u16, body: &T) -> AgentResponse {
    match serde_json::to_string(body) {
        Ok(json) => {
            AgentResponse::block(status, Some(json))
                .add_response_header(HeaderOp::Set {
                    name: "Content-Type".to_string(),
                    value: "application/scim+json".to_string(),
                })
                .with_audit(AuditMetadata {
                    tags: vec!["scim".to_string()],
                    ..Default::default()
                })
        }
        Err(_) => {
            AgentResponse::block(500, Some("Internal server error".to_string()))
                .add_response_header(HeaderOp::Set {
                    name: "Content-Type".to_string(),
                    value: "application/scim+json".to_string(),
                })
        }
    }
}

/// Build a SCIM error response.
pub fn scim_error_response(status: u16, detail: &str) -> AgentResponse {
    let err = ScimError::new(status, detail);
    match serde_json::to_string(&err) {
        Ok(json) => {
            AgentResponse::block(status, Some(json))
                .add_response_header(HeaderOp::Set {
                    name: "Content-Type".to_string(),
                    value: "application/scim+json".to_string(),
                })
                .with_audit(AuditMetadata {
                    tags: vec!["scim".to_string(), "error".to_string()],
                    ..Default::default()
                })
        }
        Err(_) => AgentResponse::block(status, Some(detail.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_matching_create() {
        assert_eq!(
            match_scim_route("/scim/v2", "/scim/v2/Users", "POST"),
            Some(ScimRoute::CreateUser)
        );
    }

    #[test]
    fn test_route_matching_get_user() {
        assert_eq!(
            match_scim_route("/scim/v2", "/scim/v2/Users/abc-123", "GET"),
            Some(ScimRoute::GetUser("abc-123".to_string()))
        );
    }

    #[test]
    fn test_route_matching_list_users() {
        assert_eq!(
            match_scim_route("/scim/v2", "/scim/v2/Users", "GET"),
            Some(ScimRoute::ListUsers)
        );
    }

    #[test]
    fn test_route_matching_list_with_query() {
        assert_eq!(
            match_scim_route("/scim/v2", "/scim/v2/Users?startIndex=1&count=10", "GET"),
            Some(ScimRoute::ListUsers)
        );
    }

    #[test]
    fn test_route_matching_replace() {
        assert_eq!(
            match_scim_route("/scim/v2", "/scim/v2/Users/abc-123", "PUT"),
            Some(ScimRoute::ReplaceUser("abc-123".to_string()))
        );
    }

    #[test]
    fn test_route_matching_patch() {
        assert_eq!(
            match_scim_route("/scim/v2", "/scim/v2/Users/abc-123", "PATCH"),
            Some(ScimRoute::PatchUser("abc-123".to_string()))
        );
    }

    #[test]
    fn test_route_matching_delete() {
        assert_eq!(
            match_scim_route("/scim/v2", "/scim/v2/Users/abc-123", "DELETE"),
            Some(ScimRoute::DeleteUser("abc-123".to_string()))
        );
    }

    #[test]
    fn test_route_matching_no_match() {
        assert_eq!(
            match_scim_route("/scim/v2", "/api/users", "GET"),
            None
        );
        assert_eq!(
            match_scim_route("/scim/v2", "/scim/v2/Groups", "GET"),
            None
        );
    }

    #[test]
    fn test_route_matching_empty_id() {
        assert_eq!(
            match_scim_route("/scim/v2", "/scim/v2/Users/", "GET"),
            None
        );
    }

    #[test]
    fn test_filter_parsing_valid() {
        let (field, value) = parse_filter(r#"externalId eq "abc-123""#).unwrap();
        assert_eq!(field, "externalId");
        assert_eq!(value, "abc-123");

        let (field, value) = parse_filter(r#"userName eq "jdoe""#).unwrap();
        assert_eq!(field, "userName");
        assert_eq!(value, "jdoe");
    }

    #[test]
    fn test_filter_parsing_unsupported_field() {
        assert!(parse_filter(r#"email eq "test@example.com""#).is_err());
    }

    #[test]
    fn test_filter_parsing_unsupported_operator() {
        assert!(parse_filter(r#"userName co "test""#).is_err());
    }

    #[test]
    fn test_filter_parsing_invalid_syntax() {
        assert!(parse_filter("invalid").is_err());
    }

    #[test]
    fn test_parse_query_params_defaults() {
        let (start, count, filter) = parse_query_params(None);
        assert_eq!(start, 1);
        assert_eq!(count, 100);
        assert!(filter.is_none());
    }

    #[test]
    fn test_parse_query_params_with_values() {
        let (start, count, filter) = parse_query_params(Some("startIndex=5&count=25"));
        assert_eq!(start, 5);
        assert_eq!(count, 25);
        assert!(filter.is_none());
    }

    #[test]
    fn test_parse_query_params_with_filter() {
        let (_, _, filter) = parse_query_params(Some("filter=userName+eq+%22test%22"));
        assert!(filter.is_some());
        assert!(filter.unwrap().contains("userName"));
    }

    #[test]
    fn test_apply_patch_replace_active() {
        let mut user = ScimUser::new("jdoe".to_string(), None, "/scim/v2");
        assert!(user.active);

        let op = PatchOperation {
            op: "replace".to_string(),
            path: Some("active".to_string()),
            value: Some(serde_json::Value::Bool(false)),
        };
        apply_patch_op(&mut user, &op).unwrap();
        assert!(!user.active);
    }

    #[test]
    fn test_apply_patch_add_name() {
        let mut user = ScimUser::new("jdoe".to_string(), None, "/scim/v2");
        assert!(user.name.is_none());

        let op = PatchOperation {
            op: "add".to_string(),
            path: Some("name.givenName".to_string()),
            value: Some(serde_json::Value::String("John".to_string())),
        };
        apply_patch_op(&mut user, &op).unwrap();
        assert_eq!(user.name.unwrap().given_name, Some("John".to_string()));
    }

    #[test]
    fn test_apply_patch_remove() {
        let mut user = ScimUser::new("jdoe".to_string(), None, "/scim/v2");
        user.display_name = Some("John Doe".to_string());

        let op = PatchOperation {
            op: "remove".to_string(),
            path: Some("displayName".to_string()),
            value: None,
        };
        apply_patch_op(&mut user, &op).unwrap();
        assert!(user.display_name.is_none());
    }

    #[test]
    fn test_apply_patch_no_path_with_object() {
        let mut user = ScimUser::new("jdoe".to_string(), None, "/scim/v2");

        let op = PatchOperation {
            op: "replace".to_string(),
            path: None,
            value: Some(serde_json::json!({
                "displayName": "Jane Doe",
                "active": false
            })),
        };
        apply_patch_op(&mut user, &op).unwrap();
        assert_eq!(user.display_name, Some("Jane Doe".to_string()));
        assert!(!user.active);
    }
}
