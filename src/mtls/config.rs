//! mTLS configuration.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// mTLS client certificate configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MtlsConfig {
    /// Enable mTLS authentication.
    #[serde(default)]
    pub enabled: bool,

    /// Header containing the client certificate (from proxy).
    /// Default: X-Client-Cert
    #[serde(default = "default_cert_header")]
    pub client_cert_header: String,

    /// Path to CA certificate for chain validation (optional).
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,

    /// Allowed Distinguished Names (exact match).
    #[serde(default)]
    pub allowed_dns: Vec<String>,

    /// Allowed Subject Alternative Names (DNS or email).
    #[serde(default)]
    pub allowed_sans: Vec<String>,

    /// Use Common Name as user ID.
    #[serde(default = "default_true")]
    pub extract_cn_as_user: bool,

    /// Use SAN email as user ID (overrides CN if present).
    #[serde(default)]
    pub extract_san_email_as_user: bool,

    /// Require client certificate (vs optional).
    #[serde(default)]
    pub require_cert: bool,

    /// Log certificate details for debugging.
    #[serde(default)]
    pub log_certs: bool,
}

fn default_cert_header() -> String {
    "X-Client-Cert".to_string()
}

fn default_true() -> bool {
    true
}

impl Default for MtlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            client_cert_header: default_cert_header(),
            ca_cert_path: None,
            allowed_dns: vec![],
            allowed_sans: vec![],
            extract_cn_as_user: true,
            extract_san_email_as_user: false,
            require_cert: false,
            log_certs: false,
        }
    }
}

impl MtlsConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        // If CA cert path specified, check it exists
        if let Some(ref path) = self.ca_cert_path {
            if !path.exists() {
                return Err(format!("CA certificate file does not exist: {:?}", path));
            }
        }

        // Warn if no allowlists configured
        if self.allowed_dns.is_empty() && self.allowed_sans.is_empty() {
            // This is a warning, not an error - might use CA validation only
            tracing::warn!("mTLS enabled but no DN or SAN allowlists configured");
        }

        Ok(())
    }

    /// Check if a Distinguished Name is allowed.
    pub fn is_dn_allowed(&self, dn: &str) -> bool {
        if self.allowed_dns.is_empty() {
            return true; // No restrictions
        }
        self.allowed_dns.iter().any(|allowed| allowed == dn)
    }

    /// Check if a SAN is allowed.
    pub fn is_san_allowed(&self, san: &str) -> bool {
        if self.allowed_sans.is_empty() {
            return true; // No restrictions
        }
        self.allowed_sans.iter().any(|allowed| allowed == san)
    }
}

/// JSON configuration for dynamic reconfiguration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct MtlsConfigJson {
    pub enabled: Option<bool>,
    pub client_cert_header: Option<String>,
    pub ca_cert_path: Option<String>,
    pub allowed_dns: Option<Vec<String>>,
    pub allowed_sans: Option<Vec<String>>,
    pub extract_cn_as_user: Option<bool>,
    pub extract_san_email_as_user: Option<bool>,
    pub require_cert: Option<bool>,
    pub log_certs: Option<bool>,
}

impl MtlsConfigJson {
    /// Apply JSON config to existing config.
    pub fn apply_to(&self, config: &mut MtlsConfig) {
        if let Some(enabled) = self.enabled {
            config.enabled = enabled;
        }
        if let Some(ref header) = self.client_cert_header {
            config.client_cert_header = header.clone();
        }
        if let Some(ref path) = self.ca_cert_path {
            config.ca_cert_path = Some(PathBuf::from(path));
        }
        if let Some(ref dns) = self.allowed_dns {
            config.allowed_dns = dns.clone();
        }
        if let Some(ref sans) = self.allowed_sans {
            config.allowed_sans = sans.clone();
        }
        if let Some(extract_cn) = self.extract_cn_as_user {
            config.extract_cn_as_user = extract_cn;
        }
        if let Some(extract_san) = self.extract_san_email_as_user {
            config.extract_san_email_as_user = extract_san;
        }
        if let Some(require) = self.require_cert {
            config.require_cert = require;
        }
        if let Some(log) = self.log_certs {
            config.log_certs = log;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MtlsConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.client_cert_header, "X-Client-Cert");
        assert!(config.extract_cn_as_user);
        assert!(!config.extract_san_email_as_user);
    }

    #[test]
    fn test_dn_allowlist() {
        let mut config = MtlsConfig::default();

        // No restrictions - allow all
        assert!(config.is_dn_allowed("CN=test,O=example"));

        // With restrictions
        config.allowed_dns = vec!["CN=allowed,O=example".to_string()];
        assert!(config.is_dn_allowed("CN=allowed,O=example"));
        assert!(!config.is_dn_allowed("CN=denied,O=example"));
    }

    #[test]
    fn test_san_allowlist() {
        let mut config = MtlsConfig::default();

        // No restrictions - allow all
        assert!(config.is_san_allowed("user@example.com"));

        // With restrictions
        config.allowed_sans = vec!["user@example.com".to_string(), "service.example.com".to_string()];
        assert!(config.is_san_allowed("user@example.com"));
        assert!(config.is_san_allowed("service.example.com"));
        assert!(!config.is_san_allowed("other@example.com"));
    }
}
