//! SAML Service Provider configuration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// SAML Service Provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlConfig {
    /// Enable SAML authentication.
    #[serde(default)]
    pub enabled: bool,

    /// SP Entity ID (unique identifier for this service provider).
    #[serde(default)]
    pub entity_id: String,

    /// Assertion Consumer Service URL (where IdP posts SAML response).
    #[serde(default)]
    pub acs_url: String,

    /// ACS path for matching incoming requests (e.g., "/saml/acs").
    #[serde(default = "default_acs_path")]
    pub acs_path: String,

    /// Single Logout Service URL (optional).
    #[serde(default)]
    pub slo_url: Option<String>,

    /// IdP metadata URL (fetched and cached on startup).
    #[serde(default)]
    pub idp_metadata_url: Option<String>,

    /// IdP metadata XML (inline, alternative to URL).
    #[serde(default)]
    pub idp_metadata_xml: Option<String>,

    /// IdP SSO URL (direct configuration, alternative to metadata).
    #[serde(default)]
    pub idp_sso_url: Option<String>,

    /// IdP Entity ID (direct configuration).
    #[serde(default)]
    pub idp_entity_id: Option<String>,

    /// IdP certificate (PEM format, for signature verification).
    #[serde(default)]
    pub idp_certificate_pem: Option<String>,

    /// SP private key (PEM format, for signing requests/decrypting assertions).
    #[serde(default)]
    pub private_key_pem: Option<String>,

    /// SP certificate (PEM format, included in SP metadata).
    #[serde(default)]
    pub certificate_pem: Option<String>,

    /// Allow unsigned assertions (NOT recommended for production).
    #[serde(default)]
    pub allow_unsigned_assertions: bool,

    /// Session TTL in seconds (default: 8 hours).
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,

    /// Cookie name for session ID.
    #[serde(default = "default_cookie_name")]
    pub session_cookie_name: String,

    /// Cookie domain (optional, defaults to request host).
    #[serde(default)]
    pub cookie_domain: Option<String>,

    /// Cookie path.
    #[serde(default = "default_cookie_path")]
    pub cookie_path: String,

    /// Require HTTPS for cookies (Secure flag).
    #[serde(default = "default_true")]
    pub cookie_secure: bool,

    /// Set HttpOnly flag on cookies.
    #[serde(default = "default_true")]
    pub cookie_http_only: bool,

    /// Use SameSite=Lax (recommended).
    #[serde(default = "default_same_site")]
    pub cookie_same_site: String,

    /// Attribute mapping: SAML attribute name -> header name.
    /// e.g., {"email": "X-Auth-Email", "groups": "X-Auth-Groups"}
    #[serde(default)]
    pub attribute_mapping: HashMap<String, String>,

    /// NameID format to request (optional).
    /// e.g., "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    #[serde(default)]
    pub name_id_format: Option<String>,

    /// Clock skew tolerance in seconds.
    #[serde(default = "default_clock_skew")]
    pub clock_skew_secs: i64,

    /// Session store path (redb database file).
    #[serde(default = "default_session_store_path")]
    pub session_store_path: String,

    /// Cleanup interval in seconds.
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,

    /// Paths to protect with SAML authentication (if empty, protects all).
    #[serde(default)]
    pub protected_paths: Vec<String>,

    /// Paths to exclude from SAML authentication.
    #[serde(default)]
    pub excluded_paths: Vec<String>,

    /// RelayState parameter name.
    #[serde(default = "default_relay_state_param")]
    pub relay_state_param: String,
}

fn default_acs_path() -> String {
    "/saml/acs".to_string()
}

fn default_session_ttl() -> u64 {
    8 * 60 * 60 // 8 hours
}

fn default_cookie_name() -> String {
    "sentinel_saml_session".to_string()
}

fn default_cookie_path() -> String {
    "/".to_string()
}

fn default_true() -> bool {
    true
}

fn default_same_site() -> String {
    "Lax".to_string()
}

fn default_clock_skew() -> i64 {
    300 // 5 minutes
}

fn default_session_store_path() -> String {
    "/var/lib/sentinel-auth/sessions.redb".to_string()
}

fn default_cleanup_interval() -> u64 {
    300 // 5 minutes
}

fn default_relay_state_param() -> String {
    "RelayState".to_string()
}

impl Default for SamlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            entity_id: String::new(),
            acs_url: String::new(),
            acs_path: default_acs_path(),
            slo_url: None,
            idp_metadata_url: None,
            idp_metadata_xml: None,
            idp_sso_url: None,
            idp_entity_id: None,
            idp_certificate_pem: None,
            private_key_pem: None,
            certificate_pem: None,
            allow_unsigned_assertions: false,
            session_ttl_secs: default_session_ttl(),
            session_cookie_name: default_cookie_name(),
            cookie_domain: None,
            cookie_path: default_cookie_path(),
            cookie_secure: true,
            cookie_http_only: true,
            cookie_same_site: default_same_site(),
            attribute_mapping: HashMap::new(),
            name_id_format: None,
            clock_skew_secs: default_clock_skew(),
            session_store_path: default_session_store_path(),
            cleanup_interval_secs: default_cleanup_interval(),
            protected_paths: Vec::new(),
            excluded_paths: Vec::new(),
            relay_state_param: default_relay_state_param(),
        }
    }
}

impl SamlConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        if self.entity_id.is_empty() {
            return Err("SAML entity_id is required".to_string());
        }

        if self.acs_url.is_empty() {
            return Err("SAML acs_url is required".to_string());
        }

        // Must have either metadata or direct IdP config
        let has_metadata = self.idp_metadata_url.is_some() || self.idp_metadata_xml.is_some();
        let has_direct_config = self.idp_sso_url.is_some() && self.idp_entity_id.is_some();

        if !has_metadata && !has_direct_config {
            return Err(
                "SAML requires either idp_metadata_url/idp_metadata_xml or idp_sso_url+idp_entity_id"
                    .to_string(),
            );
        }

        Ok(())
    }

    /// Check if a path should be protected by SAML.
    pub fn should_protect_path(&self, path: &str) -> bool {
        // Check exclusions first
        for excluded in &self.excluded_paths {
            if path.starts_with(excluded) {
                return false;
            }
        }

        // If protected_paths is empty, protect everything
        if self.protected_paths.is_empty() {
            return true;
        }

        // Check if path matches any protected pattern
        for protected in &self.protected_paths {
            if path.starts_with(protected) {
                return true;
            }
        }

        false
    }

    /// Check if the path is the ACS endpoint.
    pub fn is_acs_path(&self, path: &str) -> bool {
        path == self.acs_path || path.starts_with(&format!("{}?", self.acs_path))
    }

    /// Build the session cookie value.
    pub fn build_cookie(&self, session_id: &str) -> String {
        let mut cookie = format!("{}={}", self.session_cookie_name, session_id);

        if let Some(ref domain) = self.cookie_domain {
            cookie.push_str(&format!("; Domain={}", domain));
        }

        cookie.push_str(&format!("; Path={}", self.cookie_path));

        if self.cookie_secure {
            cookie.push_str("; Secure");
        }

        if self.cookie_http_only {
            cookie.push_str("; HttpOnly");
        }

        cookie.push_str(&format!("; SameSite={}", self.cookie_same_site));

        // Set Max-Age
        cookie.push_str(&format!("; Max-Age={}", self.session_ttl_secs));

        cookie
    }

    /// Parse session ID from cookie header.
    pub fn parse_session_cookie(&self, cookie_header: &str) -> Option<String> {
        for part in cookie_header.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix(&format!("{}=", self.session_cookie_name)) {
                return Some(value.to_string());
            }
        }
        None
    }
}

/// JSON configuration for dynamic reconfiguration via on_configure().
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct SamlConfigJson {
    pub enabled: Option<bool>,
    pub entity_id: Option<String>,
    pub acs_url: Option<String>,
    pub acs_path: Option<String>,
    pub slo_url: Option<String>,
    pub idp_metadata_url: Option<String>,
    pub idp_metadata_xml: Option<String>,
    pub idp_sso_url: Option<String>,
    pub idp_entity_id: Option<String>,
    pub idp_certificate_pem: Option<String>,
    pub private_key_pem: Option<String>,
    pub certificate_pem: Option<String>,
    #[serde(default)]
    pub allow_unsigned_assertions: bool,
    pub session_ttl_secs: Option<u64>,
    pub session_cookie_name: Option<String>,
    pub cookie_domain: Option<String>,
    pub cookie_path: Option<String>,
    pub cookie_secure: Option<bool>,
    pub cookie_http_only: Option<bool>,
    pub cookie_same_site: Option<String>,
    #[serde(default)]
    pub attribute_mapping: HashMap<String, String>,
    pub name_id_format: Option<String>,
    pub clock_skew_secs: Option<i64>,
    pub session_store_path: Option<String>,
    #[serde(default)]
    pub protected_paths: Vec<String>,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
}

impl SamlConfigJson {
    /// Merge JSON config into existing config.
    pub fn apply_to(&self, config: &mut SamlConfig) {
        if let Some(enabled) = self.enabled {
            config.enabled = enabled;
        }
        if let Some(ref entity_id) = self.entity_id {
            config.entity_id = entity_id.clone();
        }
        if let Some(ref acs_url) = self.acs_url {
            config.acs_url = acs_url.clone();
        }
        if let Some(ref acs_path) = self.acs_path {
            config.acs_path = acs_path.clone();
        }
        if let Some(ref slo_url) = self.slo_url {
            config.slo_url = Some(slo_url.clone());
        }
        if let Some(ref url) = self.idp_metadata_url {
            config.idp_metadata_url = Some(url.clone());
        }
        if let Some(ref xml) = self.idp_metadata_xml {
            config.idp_metadata_xml = Some(xml.clone());
        }
        if let Some(ref url) = self.idp_sso_url {
            config.idp_sso_url = Some(url.clone());
        }
        if let Some(ref id) = self.idp_entity_id {
            config.idp_entity_id = Some(id.clone());
        }
        if let Some(ref pem) = self.idp_certificate_pem {
            config.idp_certificate_pem = Some(pem.clone());
        }
        if let Some(ref pem) = self.private_key_pem {
            config.private_key_pem = Some(pem.clone());
        }
        if let Some(ref pem) = self.certificate_pem {
            config.certificate_pem = Some(pem.clone());
        }
        config.allow_unsigned_assertions = self.allow_unsigned_assertions;
        if let Some(ttl) = self.session_ttl_secs {
            config.session_ttl_secs = ttl;
        }
        if let Some(ref name) = self.session_cookie_name {
            config.session_cookie_name = name.clone();
        }
        if let Some(ref domain) = self.cookie_domain {
            config.cookie_domain = Some(domain.clone());
        }
        if let Some(ref path) = self.cookie_path {
            config.cookie_path = path.clone();
        }
        if let Some(secure) = self.cookie_secure {
            config.cookie_secure = secure;
        }
        if let Some(http_only) = self.cookie_http_only {
            config.cookie_http_only = http_only;
        }
        if let Some(ref same_site) = self.cookie_same_site {
            config.cookie_same_site = same_site.clone();
        }
        if !self.attribute_mapping.is_empty() {
            config.attribute_mapping = self.attribute_mapping.clone();
        }
        if let Some(ref format) = self.name_id_format {
            config.name_id_format = Some(format.clone());
        }
        if let Some(skew) = self.clock_skew_secs {
            config.clock_skew_secs = skew;
        }
        if let Some(ref path) = self.session_store_path {
            config.session_store_path = path.clone();
        }
        if !self.protected_paths.is_empty() {
            config.protected_paths = self.protected_paths.clone();
        }
        if !self.excluded_paths.is_empty() {
            config.excluded_paths = self.excluded_paths.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SamlConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.session_ttl_secs, 8 * 60 * 60);
        assert_eq!(config.cookie_path, "/");
        assert!(config.cookie_secure);
        assert!(config.cookie_http_only);
    }

    #[test]
    fn test_validation() {
        let mut config = SamlConfig::default();
        assert!(config.validate().is_ok()); // disabled is valid

        config.enabled = true;
        assert!(config.validate().is_err()); // missing entity_id

        config.entity_id = "https://sp.example.com".to_string();
        assert!(config.validate().is_err()); // missing acs_url

        config.acs_url = "https://sp.example.com/saml/acs".to_string();
        assert!(config.validate().is_err()); // missing IdP config

        config.idp_sso_url = Some("https://idp.example.com/sso".to_string());
        config.idp_entity_id = Some("https://idp.example.com".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_path_protection() {
        let mut config = SamlConfig::default();
        config.enabled = true;

        // Empty protected_paths = protect everything
        assert!(config.should_protect_path("/api/users"));
        assert!(config.should_protect_path("/admin"));

        // Add exclusion
        config.excluded_paths = vec!["/health".to_string(), "/metrics".to_string()];
        assert!(!config.should_protect_path("/health"));
        assert!(!config.should_protect_path("/metrics"));
        assert!(config.should_protect_path("/api/users"));

        // Add specific protected paths
        config.protected_paths = vec!["/api".to_string(), "/admin".to_string()];
        assert!(config.should_protect_path("/api/users"));
        assert!(config.should_protect_path("/admin/settings"));
        assert!(!config.should_protect_path("/public/docs"));
    }

    #[test]
    fn test_cookie_parsing() {
        let config = SamlConfig::default();
        let cookie = "other=value; sentinel_saml_session=abc123def456; another=test";
        assert_eq!(
            config.parse_session_cookie(cookie),
            Some("abc123def456".to_string())
        );

        assert_eq!(config.parse_session_cookie("no_session=here"), None);
    }

    #[test]
    fn test_cookie_building() {
        let mut config = SamlConfig::default();
        config.cookie_domain = Some("example.com".to_string());

        let cookie = config.build_cookie("session123");
        assert!(cookie.contains("sentinel_saml_session=session123"));
        assert!(cookie.contains("Domain=example.com"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
    }
}
