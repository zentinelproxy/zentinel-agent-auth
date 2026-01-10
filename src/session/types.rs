//! Session types for SAML authentication persistence.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique session identifier (16-byte random value, hex-encoded for storage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId([u8; 16]);

impl SessionId {
    /// Generate a new random session ID.
    pub fn new() -> Self {
        Self(rand::random())
    }

    /// Convert to hex string for storage/cookies.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        if bytes.len() != 16 {
            return None;
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Some(Self(arr))
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A stored SAML session with user attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID.
    pub id: SessionId,

    /// User identifier (from SAML NameID).
    pub user_id: String,

    /// SAML NameID format (e.g., emailAddress, persistent).
    pub name_id_format: Option<String>,

    /// Session creation time.
    pub created_at: DateTime<Utc>,

    /// Session expiry time.
    pub expires_at: DateTime<Utc>,

    /// Last access time (updated on each request).
    pub last_accessed: DateTime<Utc>,

    /// SAML assertion attributes as key → values.
    /// Most attributes are single-valued, but SAML allows multi-valued.
    pub attributes: HashMap<String, Vec<String>>,

    /// Original SAML assertion ID (for replay prevention).
    pub assertion_id: String,

    /// IdP entity ID that issued this session.
    pub idp_entity_id: String,

    /// Session index from SAML assertion (for Single Logout).
    pub session_index: Option<String>,

    /// Client IP at session creation (optional binding).
    pub client_ip: Option<String>,
}

impl Session {
    /// Create a new session with the given parameters.
    pub fn new(
        user_id: String,
        assertion_id: String,
        idp_entity_id: String,
        ttl_secs: u64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::new(),
            user_id,
            name_id_format: None,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_secs as i64),
            last_accessed: now,
            attributes: HashMap::new(),
            assertion_id,
            idp_entity_id,
            session_index: None,
            client_ip: None,
        }
    }

    /// Check if the session is expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Update last accessed time.
    pub fn touch(&mut self) {
        self.last_accessed = Utc::now();
    }

    /// Get a single-valued attribute.
    pub fn get_attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .get(name)
            .and_then(|values| values.first())
            .map(|s| s.as_str())
    }

    /// Set a single-valued attribute.
    pub fn set_attribute(&mut self, name: String, value: String) {
        self.attributes.insert(name, vec![value]);
    }

    /// Set a multi-valued attribute.
    pub fn set_attributes(&mut self, name: String, values: Vec<String>) {
        self.attributes.insert(name, values);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_roundtrip() {
        let id = SessionId::new();
        let hex = id.to_hex();
        let parsed = SessionId::from_hex(&hex).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_session_id_invalid_hex() {
        assert!(SessionId::from_hex("not-valid-hex").is_none());
        assert!(SessionId::from_hex("abcd").is_none()); // too short
        assert!(SessionId::from_hex("").is_none());
    }

    #[test]
    fn test_session_expiry() {
        let mut session = Session::new(
            "user@example.com".to_string(),
            "assertion-123".to_string(),
            "https://idp.example.com".to_string(),
            3600, // 1 hour
        );
        assert!(!session.is_expired());

        // Manually expire the session
        session.expires_at = Utc::now() - chrono::Duration::seconds(10);
        assert!(session.is_expired());
    }

    #[test]
    fn test_session_attributes() {
        let mut session = Session::new(
            "user@example.com".to_string(),
            "assertion-123".to_string(),
            "https://idp.example.com".to_string(),
            3600,
        );

        session.set_attribute("email".to_string(), "user@example.com".to_string());
        session.set_attributes(
            "groups".to_string(),
            vec!["admin".to_string(), "users".to_string()],
        );

        assert_eq!(session.get_attribute("email"), Some("user@example.com"));
        assert_eq!(session.get_attribute("groups"), Some("admin")); // first value
        assert_eq!(session.get_attribute("missing"), None);
    }
}
