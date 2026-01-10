//! SAML Service Provider implementation.
//!
//! Handles SP-initiated SSO flow.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{debug, info};

use super::config::SamlConfig;
use crate::session::{Session, SessionStore};

/// SAML Service Provider that handles authentication.
pub struct SamlProvider {
    /// SP configuration.
    config: RwLock<SamlConfig>,
}

impl SamlProvider {
    /// Create a new SAML provider with the given configuration.
    pub fn new(config: SamlConfig) -> Result<Self> {
        if config.enabled {
            config.validate().map_err(|e| anyhow!(e))?;
        }

        Ok(Self {
            config: RwLock::new(config),
        })
    }

    /// Update configuration.
    pub fn reconfigure(&self, config: SamlConfig) -> Result<()> {
        if config.enabled {
            config.validate().map_err(|e| anyhow!(e))?;
        }

        let mut cfg = self
            .config
            .write()
            .map_err(|_| anyhow!("Config lock poisoned"))?;
        *cfg = config;

        Ok(())
    }

    /// Check if SAML is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.read().map(|c| c.enabled).unwrap_or(false)
    }

    /// Get a clone of the current config.
    pub fn config(&self) -> Result<SamlConfig> {
        self.config
            .read()
            .map(|c| c.clone())
            .map_err(|_| anyhow!("Config lock poisoned"))
    }

    /// Create an AuthnRequest and return the redirect URL to the IdP.
    pub fn create_authn_request(&self, relay_state: Option<&str>) -> Result<String> {
        let config = self.config()?;

        let idp_sso_url = config
            .idp_sso_url
            .as_ref()
            .ok_or_else(|| anyhow!("IdP SSO URL not configured"))?;

        // Build a simple SAML AuthnRequest XML
        let request_id = format!("_id{}", uuid::Uuid::new_v4());
        let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let authn_request = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="{}"
                Version="2.0"
                IssueInstant="{}"
                Destination="{}"
                AssertionConsumerServiceURL="{}">
                <saml:Issuer>{}</saml:Issuer>
            </samlp:AuthnRequest>"#,
            request_id, issue_instant, idp_sso_url, config.acs_url, config.entity_id
        );

        // Deflate and base64 encode
        let encoded = deflate_and_encode(&authn_request)?;

        // Build redirect URL
        let mut url = format!(
            "{}?SAMLRequest={}",
            idp_sso_url,
            urlencoding::encode(&encoded)
        );

        if let Some(state) = relay_state {
            url.push_str(&format!("&RelayState={}", urlencoding::encode(state)));
        }

        debug!(url = %url, "Created SAML AuthnRequest redirect");
        Ok(url)
    }

    /// Process a SAML Response from the IdP ACS POST.
    ///
    /// Returns the extracted user ID and attributes on success.
    pub fn process_response(
        &self,
        saml_response: &str,
        session_store: &SessionStore,
    ) -> Result<ProcessedAssertion> {
        let config = self.config()?;

        // Decode the response
        let response_xml = BASE64
            .decode(saml_response)
            .context("Failed to decode SAML response")?;
        let response_str =
            String::from_utf8(response_xml).context("SAML response is not valid UTF-8")?;

        debug!("Processing SAML response");

        // Parse the response using samael
        let response: samael::schema::Response = response_str
            .parse()
            .context("Failed to parse SAML response")?;

        // Validate response status
        if let Some(ref status) = response.status {
            let status_value = status.status_code.value.as_deref();
            if status_value != Some("urn:oasis:names:tc:SAML:2.0:status:Success") {
                let message = status
                    .status_message
                    .as_ref()
                    .and_then(|m| m.value.clone())
                    .unwrap_or_else(|| "Unknown error".to_string());
                return Err(anyhow!("SAML authentication failed: {}", message));
            }
        }

        // Extract assertion
        let assertion = response
            .assertion
            .as_ref()
            .ok_or_else(|| anyhow!("SAML response contains no assertion"))?;

        // Validate timestamps with clock skew tolerance
        let now = Utc::now();
        let skew = Duration::seconds(config.clock_skew_secs);

        if let Some(ref conditions) = assertion.conditions {
            if let Some(not_before) = conditions.not_before {
                if now < not_before - skew {
                    return Err(anyhow!("SAML assertion not yet valid"));
                }
            }
            if let Some(not_on_or_after) = conditions.not_on_or_after {
                if now >= not_on_or_after + skew {
                    return Err(anyhow!("SAML assertion has expired"));
                }
            }
        }

        // Get assertion ID for replay prevention
        let assertion_id = assertion.id.clone();

        // Check for replay
        if session_store.is_assertion_used(&assertion_id)? {
            return Err(anyhow!("SAML assertion replay detected"));
        }

        // Extract subject (user ID)
        let subject = assertion
            .subject
            .as_ref()
            .ok_or_else(|| anyhow!("SAML assertion missing subject"))?;

        let name_id = subject
            .name_id
            .as_ref()
            .ok_or_else(|| anyhow!("SAML assertion missing NameID"))?;

        let user_id = name_id.value.clone();
        let name_id_format = name_id.format.clone();

        // Extract session index from authn statements
        let session_index = assertion
            .authn_statements
            .as_ref()
            .and_then(|stmts| stmts.first())
            .and_then(|s| s.session_index.clone());

        // Extract IdP entity ID from issuer
        let idp_entity_id = assertion.issuer.value.clone().unwrap_or_else(|| "unknown".to_string());

        // Extract attributes
        let mut attributes: HashMap<String, Vec<String>> = HashMap::new();

        if let Some(ref attr_statements) = assertion.attribute_statements {
            for attr_statement in attr_statements {
                for attr in &attr_statement.attributes {
                    if let Some(ref name) = attr.name {
                        let values: Vec<String> = attr
                            .values
                            .iter()
                            .filter_map(|v| v.value.clone())
                            .collect();
                        if !values.is_empty() {
                            attributes.insert(name.clone(), values);
                        }
                    }
                }
            }
        }

        info!(
            user_id = %user_id,
            idp = %idp_entity_id,
            attributes = attributes.len(),
            "SAML assertion validated"
        );

        Ok(ProcessedAssertion {
            user_id,
            name_id_format,
            assertion_id,
            idp_entity_id,
            session_index,
            attributes,
        })
    }

    /// Create a session from a processed assertion.
    pub fn create_session(
        &self,
        assertion: ProcessedAssertion,
        session_store: &SessionStore,
        client_ip: Option<String>,
    ) -> Result<Session> {
        let config = self.config()?;

        let mut session = Session::new(
            assertion.user_id,
            assertion.assertion_id,
            assertion.idp_entity_id,
            config.session_ttl_secs,
        );

        session.name_id_format = assertion.name_id_format;
        session.session_index = assertion.session_index;
        session.client_ip = client_ip;
        session.attributes = assertion.attributes;

        // Store the session
        session_store.create(session.clone())?;

        Ok(session)
    }
}

/// Result of processing a SAML assertion.
#[derive(Debug)]
pub struct ProcessedAssertion {
    pub user_id: String,
    pub name_id_format: Option<String>,
    pub assertion_id: String,
    pub idp_entity_id: String,
    pub session_index: Option<String>,
    pub attributes: HashMap<String, Vec<String>>,
}

/// Deflate and base64 encode for SAML redirect binding.
fn deflate_and_encode(xml: &str) -> Result<String> {
    use std::io::Write;

    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(xml.as_bytes())?;
    let compressed = encoder.finish()?;
    Ok(BASE64.encode(compressed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SamlConfig {
        SamlConfig {
            enabled: true,
            entity_id: "https://sp.example.com".to_string(),
            acs_url: "https://sp.example.com/saml/acs".to_string(),
            idp_sso_url: Some("https://idp.example.com/sso".to_string()),
            idp_entity_id: Some("https://idp.example.com".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_provider_creation() {
        let config = test_config();
        let provider = SamlProvider::new(config).unwrap();
        assert!(provider.is_enabled());
    }

    #[test]
    fn test_provider_disabled() {
        let config = SamlConfig::default();
        let provider = SamlProvider::new(config).unwrap();
        assert!(!provider.is_enabled());
    }

    #[test]
    fn test_create_authn_request() {
        let config = test_config();
        let provider = SamlProvider::new(config).unwrap();

        let url = provider.create_authn_request(Some("/dashboard")).unwrap();
        assert!(url.starts_with("https://idp.example.com/sso?"));
        assert!(url.contains("SAMLRequest="));
        assert!(url.contains("RelayState="));
    }
}
