//! SAML Service Provider implementation.
//!
//! Handles SP-initiated SSO flow. A response is accepted only if:
//!
//! - it has the shape [`super::verify::check_response_structure`] allows;
//! - every XML signature in it verifies against the configured IdP signing
//!   certificate (samael / libxmlsec1, exclusive c14n), and only the signed
//!   content is read;
//! - it answers an AuthnRequest this provider issued (`InResponseTo`), names
//!   this SP's ACS URL as `Destination`, comes from the configured IdP
//!   entity, is addressed to this SP (`Audience`) and is within its validity
//!   window;
//! - its assertion has not been used before.
#![allow(dead_code)]

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Duration, Utc};
use samael::metadata::EntityDescriptor;
use samael::service_provider::{ServiceProvider, ServiceProviderBuilder};
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::Instant;
use tracing::{debug, info};

use super::config::SamlConfig;
use super::verify::check_response_structure;
use crate::session::{Session, SessionStore};

/// How long an issued AuthnRequest may be answered.
const AUTHN_REQUEST_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// At most this many AuthnRequests are outstanding; the oldest are forgotten
/// first (their logins then fail and are retried, nothing is let through).
const MAX_OUTSTANDING_REQUESTS: usize = 10_000;

const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// SAML Service Provider that handles authentication.
pub struct SamlProvider {
    /// SP configuration.
    config: RwLock<SamlConfig>,
    /// samael service provider holding the IdP signing certificate(s).
    sp: RwLock<Option<ServiceProvider>>,
    /// IDs of AuthnRequests issued and not yet answered.
    outstanding: Mutex<HashMap<String, Instant>>,
}

/// Escape a value for use in an XML attribute or text node.
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The IdP metadata signatures are checked against.
///
/// Either the configured metadata XML, or metadata built from the configured
/// IdP certificate and entity ID. Fails unless it yields at least one signing
/// certificate: samael skips signature verification entirely when the IdP
/// metadata has none, so that case must never reach it.
fn idp_metadata(config: &SamlConfig) -> Result<EntityDescriptor> {
    let metadata: EntityDescriptor = if let Some(ref pem) = config.idp_certificate_pem {
        let entity_id = config
            .idp_entity_id
            .as_ref()
            .ok_or_else(|| anyhow!("SAML idp-entity-id is required with idp-certificate-pem"))?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem.trim().as_bytes())
            .map_err(|e| anyhow!("SAML idp-certificate-pem is not a PEM certificate: {e:?}"))?;
        pem.parse_x509()
            .map_err(|e| anyhow!("SAML idp-certificate-pem is not an X.509 certificate: {e:?}"))?;
        let xml = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>"#,
            entity_id = xml_escape(entity_id),
            cert = BASE64.encode(&pem.contents),
        );
        xml.parse()
            .map_err(|e| anyhow!("SAML IdP metadata could not be built: {e}"))?
    } else if let Some(ref xml) = config.idp_metadata_xml {
        let metadata: EntityDescriptor = xml
            .parse()
            .map_err(|e| anyhow!("SAML idp-metadata-xml does not parse: {e}"))?;
        if let Some(ref expected) = config.idp_entity_id {
            if metadata.entity_id.as_ref() != Some(expected) {
                bail!("SAML idp-metadata-xml is for another entity than idp-entity-id");
            }
        }
        metadata
    } else {
        bail!(
            "SAML needs the IdP signing certificate: set idp-certificate-pem \
             (with idp-entity-id) or idp-metadata-xml"
        );
    };

    if metadata.entity_id.as_deref().unwrap_or("").is_empty() {
        bail!("SAML IdP metadata has no entityID");
    }
    let sp = ServiceProvider {
        idp_metadata: metadata.clone(),
        ..Default::default()
    };
    match sp.idp_signing_certs() {
        Ok(Some(certs)) if !certs.is_empty() => Ok(metadata),
        Ok(_) => bail!("SAML IdP metadata contains no signing certificate"),
        Err(e) => bail!("SAML IdP signing certificate does not parse: {e}"),
    }
}

/// Build the samael service provider used to verify responses.
fn build_service_provider(config: &SamlConfig) -> Result<ServiceProvider> {
    let metadata = idp_metadata(config)?;
    ServiceProviderBuilder::default()
        .entity_id(Some(config.entity_id.clone()))
        .acs_url(Some(config.acs_url.clone()))
        .idp_metadata(metadata)
        .allow_idp_initiated(false)
        .max_clock_skew(Duration::seconds(config.clock_skew_secs))
        .build()
        .map_err(|e| anyhow!("SAML service provider: {e}"))
}

impl SamlProvider {
    /// Create a new SAML provider with the given configuration.
    pub fn new(config: SamlConfig) -> Result<Self> {
        let sp = if config.enabled {
            config.validate().map_err(|e| anyhow!(e))?;
            Some(build_service_provider(&config)?)
        } else {
            None
        };

        Ok(Self {
            config: RwLock::new(config),
            sp: RwLock::new(sp),
            outstanding: Mutex::new(HashMap::new()),
        })
    }

    /// Update configuration.
    pub fn reconfigure(&self, config: SamlConfig) -> Result<()> {
        let sp = if config.enabled {
            config.validate().map_err(|e| anyhow!(e))?;
            Some(build_service_provider(&config)?)
        } else {
            None
        };

        let mut cfg = self
            .config
            .write()
            .map_err(|_| anyhow!("Config lock poisoned"))?;
        let mut sp_guard = self
            .sp
            .write()
            .map_err(|_| anyhow!("SAML service provider lock poisoned"))?;
        *cfg = config;
        *sp_guard = sp;

        Ok(())
    }

    /// Remember an issued AuthnRequest ID.
    pub(crate) fn remember_request(&self, id: &str) {
        let Ok(mut outstanding) = self.outstanding.lock() else {
            return;
        };
        let now = Instant::now();
        outstanding.retain(|_, issued| now.duration_since(*issued) < AUTHN_REQUEST_TTL);
        while outstanding.len() >= MAX_OUTSTANDING_REQUESTS {
            let Some(oldest) = outstanding
                .iter()
                .min_by_key(|(_, issued)| **issued)
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            outstanding.remove(&oldest);
        }
        outstanding.insert(id.to_string(), now);
    }

    /// IDs of AuthnRequests that may still be answered.
    fn outstanding_requests(&self) -> Vec<String> {
        let Ok(outstanding) = self.outstanding.lock() else {
            return Vec::new();
        };
        let now = Instant::now();
        outstanding
            .iter()
            .filter(|(_, issued)| now.duration_since(**issued) < AUTHN_REQUEST_TTL)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// An AuthnRequest is answered at most once.
    fn consume_request(&self, id: &str) -> bool {
        self.outstanding
            .lock()
            .map(|mut o| o.remove(id).is_some())
            .unwrap_or(false)
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
        self.remember_request(&request_id);
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
            .decode(saml_response.trim())
            .context("Failed to decode SAML response")?;
        let response_str =
            String::from_utf8(response_xml).context("SAML response is not valid UTF-8")?;

        debug!("Processing SAML response");

        // Narrow the document to the shape signature verification is sound
        // for (see verify.rs), then verify every signature against the IdP
        // certificate and read only what the signatures cover.
        check_response_structure(&response_str)?;

        let sp = self
            .sp
            .read()
            .map_err(|_| anyhow!("SAML service provider lock poisoned"))?
            .clone()
            .ok_or_else(|| anyhow!("SAML is not enabled"))?;
        let outstanding = self.outstanding_requests();
        let outstanding_refs: Vec<&str> = outstanding.iter().map(String::as_str).collect();
        let assertion = sp
            .parse_xml_response(&response_str, Some(&outstanding_refs))
            .map_err(|e| anyhow!("SAML response rejected: {e}"))?;

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

        // Web SSO profile: the assertion must be restricted to this SP. samael
        // only checks the audience when an AudienceRestriction is present, so
        // require one; each restriction must include this SP (they are ANDed).
        let restrictions = assertion
            .conditions
            .as_ref()
            .and_then(|c| c.audience_restrictions.as_deref())
            .unwrap_or_default();
        if restrictions.is_empty()
            || !restrictions
                .iter()
                .all(|r| r.audience.contains(&config.entity_id))
        {
            bail!("SAML assertion is not restricted to this SP's audience");
        }

        // Web SSO profile: a bearer confirmation for this ACS, answering one
        // of our requests, and still valid.
        let request_id = assertion
            .subject
            .as_ref()
            .and_then(|s| s.subject_confirmations.as_ref())
            .into_iter()
            .flatten()
            .filter(|c| c.method.as_deref() == Some(BEARER))
            .filter_map(|c| c.subject_confirmation_data.as_ref())
            .find(|d| {
                d.recipient.as_deref() == Some(config.acs_url.as_str())
                    && d.not_on_or_after.is_some_and(|t| now < t + skew)
                    && d.not_before.is_none_or(|t| now >= t - skew)
                    && d.in_response_to
                        .as_deref()
                        .is_some_and(|id| outstanding.iter().any(|o| o == id))
            })
            .and_then(|d| d.in_response_to.clone())
            .ok_or_else(|| {
                anyhow!("SAML assertion has no valid bearer confirmation for this ACS")
            })?;

        // Get assertion ID for replay prevention
        let assertion_id = assertion.id.clone();

        // Check for replay
        if session_store.is_assertion_used(&assertion_id)? {
            return Err(anyhow!("SAML assertion replay detected"));
        }
        if !self.consume_request(&request_id) {
            return Err(anyhow!("SAML response answers a request already answered"));
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
        let idp_entity_id = assertion
            .issuer
            .value
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        // Extract attributes
        let mut attributes: HashMap<String, Vec<String>> = HashMap::new();

        if let Some(ref attr_statements) = assertion.attribute_statements {
            for attr_statement in attr_statements {
                for attr in &attr_statement.attributes {
                    if let Some(ref name) = attr.name {
                        let values: Vec<String> =
                            attr.values.iter().filter_map(|v| v.value.clone()).collect();
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
    use crate::saml::test_support::{Idp, ACS_URL, IDP_ENTITY, SP_ENTITY};
    use samael::traits::ToXml;

    const REQUEST_ID: &str = "_req-0123456789";

    fn test_config() -> SamlConfig {
        SamlConfig {
            enabled: true,
            entity_id: SP_ENTITY.to_string(),
            acs_url: ACS_URL.to_string(),
            idp_sso_url: Some("https://idp.example.com/sso".to_string()),
            idp_entity_id: Some(IDP_ENTITY.to_string()),
            idp_certificate_pem: Some(
                "-----BEGIN CERTIFICATE-----\nMIIBkjCB/AIJAOUHvh4oD+yrMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\n-----END CERTIFICATE-----"
                    .to_string(),
            ),
            ..Default::default()
        }
    }

    /// A provider trusting `idp`, waiting on [`REQUEST_ID`].
    fn provider_for(idp: &Idp) -> SamlProvider {
        let config = SamlConfig {
            idp_certificate_pem: Some(idp.cert_pem()),
            ..test_config()
        };
        let provider = SamlProvider::new(config).unwrap();
        provider.remember_request(REQUEST_ID);
        provider
    }

    fn store() -> (tempfile::TempDir, SessionStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::open(dir.path().join("sessions.redb"), 3600).unwrap();
        (dir, store)
    }

    fn post(
        provider: &SamlProvider,
        store: &SessionStore,
        xml: &str,
    ) -> Result<ProcessedAssertion> {
        provider.process_response(&BASE64.encode(xml), store)
    }

    #[test]
    fn test_provider_creation() {
        let idp = Idp::new();
        let provider = provider_for(&idp);
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
        let idp = Idp::new();
        let provider = provider_for(&idp);

        let url = provider.create_authn_request(Some("/dashboard")).unwrap();
        assert!(url.starts_with("https://idp.example.com/sso?"));
        assert!(url.contains("SAMLRequest="));
        assert!(url.contains("RelayState="));
        assert_eq!(provider.outstanding_requests().len(), 2);
    }

    #[test]
    fn a_provider_without_an_idp_signing_certificate_is_refused() {
        let config = SamlConfig {
            idp_certificate_pem: None,
            ..test_config()
        };
        assert!(SamlProvider::new(config).is_err());

        let config = SamlConfig {
            idp_certificate_pem: Some("not a certificate".to_string()),
            ..test_config()
        };
        assert!(SamlProvider::new(config).is_err());
    }

    #[test]
    fn a_response_signed_by_the_idp_is_accepted() {
        let idp = Idp::new();
        let provider = provider_for(&idp);
        let (_dir, store) = store();

        let assertion = post(
            &provider,
            &store,
            &idp.signed_xml("alice@example.com", REQUEST_ID),
        )
        .expect("a correctly signed response must be accepted");
        assert_eq!(assertion.user_id, "alice@example.com");
        assert_eq!(assertion.idp_entity_id, IDP_ENTITY);
    }

    /// The bug in #6: an unsigned response was accepted for any NameID.
    #[test]
    fn an_unsigned_response_is_rejected() {
        let idp = Idp::new();
        let provider = provider_for(&idp);
        let (_dir, store) = store();

        let mut response = idp.template("admin@example.com", REQUEST_ID);
        response.signature = None;
        let xml = response.to_string().unwrap();
        assert!(!xml.contains("Signature"));

        let err = post(&provider, &store, &xml).unwrap_err().to_string();
        assert!(err.contains("not signed"), "{err}");
    }

    #[test]
    fn a_response_with_a_tampered_name_id_is_rejected() {
        let idp = Idp::new();
        let provider = provider_for(&idp);
        let (_dir, store) = store();

        let signed = idp.signed_xml("alice@example.com", REQUEST_ID);
        let tampered = signed.replace("alice@example.com", "admin@example.com");
        assert_ne!(signed, tampered);

        let err = post(&provider, &store, &tampered).unwrap_err().to_string();
        assert!(err.contains("must be signed"), "{err}");
    }

    #[test]
    fn a_response_signed_by_another_key_is_rejected() {
        let idp = Idp::new();
        let attacker = Idp::new();
        let provider = provider_for(&idp);
        let (_dir, store) = store();

        // Correctly signed, carrying its own certificate in KeyInfo: the key
        // in the document must not be trusted, only the configured one.
        let forged = attacker.signed_xml("admin@example.com", REQUEST_ID);
        let err = post(&provider, &store, &forged).unwrap_err().to_string();
        assert!(err.contains("must be signed"), "{err}");
    }

    /// Signature wrapping: a signed response with a second, unsigned
    /// assertion for another user must not authenticate that user.
    #[test]
    fn a_wrapped_unsigned_assertion_is_rejected() {
        let idp = Idp::new();
        let provider = provider_for(&idp);
        let (_dir, store) = store();

        let signed = idp.signed_xml("alice@example.com", REQUEST_ID);
        let forged_assertion = {
            let mut forged = idp.template("admin@example.com", REQUEST_ID);
            let mut assertion = forged.assertion.take().unwrap();
            assertion.id = "_forged".to_string();
            forged.assertion = Some(assertion);
            forged.signature = None;
            let xml = forged.to_string().unwrap();
            let start = xml
                .find("<saml2:Assertion")
                .or_else(|| xml.find("<saml:Assertion"))
                .unwrap();
            let end_tag = if xml.contains("</saml2:Assertion>") {
                "</saml2:Assertion>"
            } else {
                "</saml:Assertion>"
            };
            let end = xml.find(end_tag).unwrap() + end_tag.len();
            xml[start..end].to_string()
        };

        // Before the signed assertion, and after it.
        let at = signed
            .find("<saml2:Assertion")
            .or_else(|| signed.find("<saml:Assertion"))
            .unwrap();
        let before = format!("{}{}{}", &signed[..at], forged_assertion, &signed[at..]);
        let close = signed
            .rfind("</saml2p:Response>")
            .or_else(|| signed.rfind("</samlp:Response>"))
            .unwrap();
        let after = format!(
            "{}{}{}",
            &signed[..close],
            forged_assertion,
            &signed[close..]
        );

        for (place, xml) in [("before", before), ("after", after)] {
            match post(&provider, &store, &xml) {
                Ok(a) => panic!("{place}: wrapped response accepted for {}", a.user_id),
                Err(e) => assert!(
                    e.to_string().contains("more than one assertion"),
                    "{place}: {e}"
                ),
            }
        }
    }

    /// Signature wrapping by duplicate ID: a forged element carrying the ID
    /// the signature references.
    #[test]
    fn a_duplicated_signed_id_is_rejected() {
        let idp = Idp::new();
        let provider = provider_for(&idp);
        let (_dir, store) = store();

        let signed = idp.signed_xml("alice@example.com", REQUEST_ID);
        let response_id = {
            let doc = libxml::parser::Parser::default()
                .parse_string(&signed)
                .unwrap();
            doc.get_root_element().unwrap().get_attribute("ID").unwrap()
        };
        let at = signed
            .find("<saml2:Assertion")
            .or_else(|| signed.find("<saml:Assertion"))
            .unwrap();
        let xml = format!(
            "{}<Extensions xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"{}\"/>{}",
            &signed[..at],
            response_id,
            &signed[at..]
        );
        let err = post(&provider, &store, &xml).unwrap_err().to_string();
        assert!(err.contains("more than once"), "{err}");
    }

    /// A comment inside the signed NameID does not change the canonicalised
    /// (and so the signed) text, but can split the text the SP reads.
    #[test]
    fn a_comment_injected_into_a_signed_name_id_is_rejected() {
        let idp = Idp::new();
        let provider = provider_for(&idp);
        let (_dir, store) = store();

        let signed = idp.signed_xml("admin@example.com.attacker.test", REQUEST_ID);
        let injected = signed.replace(
            "admin@example.com.attacker.test",
            "admin@example.com<!---->.attacker.test",
        );
        assert_ne!(signed, injected);
        let err = post(&provider, &store, &injected).unwrap_err().to_string();
        assert!(err.contains("comment"), "{err}");
    }

    #[test]
    fn a_response_to_no_request_of_ours_is_rejected() {
        let idp = Idp::new();
        let provider = provider_for(&idp);
        let (_dir, store) = store();

        let unsolicited = idp.signed_xml("alice@example.com", "_never-issued");
        assert!(post(&provider, &store, &unsolicited).is_err());
    }

    #[test]
    fn a_response_is_accepted_once() {
        let idp = Idp::new();
        let provider = provider_for(&idp);
        let (_dir, store) = store();

        let xml = idp.signed_xml("alice@example.com", REQUEST_ID);
        let assertion = post(&provider, &store, &xml).unwrap();
        provider.create_session(assertion, &store, None).unwrap();
        assert!(
            post(&provider, &store, &xml).is_err(),
            "replayed response accepted"
        );

        // A fresh response to an already answered request is refused too.
        let again = idp.signed_xml("alice@example.com", REQUEST_ID);
        assert!(post(&provider, &store, &again).is_err());
    }

    #[test]
    fn a_response_for_another_acs_is_rejected() {
        let idp = Idp::new();
        let (_dir, store) = store();
        let config = SamlConfig {
            idp_certificate_pem: Some(idp.cert_pem()),
            acs_url: "https://other.example.com/saml/acs".to_string(),
            ..test_config()
        };
        let provider = SamlProvider::new(config).unwrap();
        provider.remember_request(REQUEST_ID);
        assert!(post(
            &provider,
            &store,
            &idp.signed_xml("alice@example.com", REQUEST_ID)
        )
        .is_err());
    }

    /// The Web SSO profile requires an AudienceRestriction naming the SP;
    /// samael accepts an assertion without one.
    #[test]
    fn an_assertion_without_an_audience_restriction_is_rejected() {
        let idp = Idp::new();
        let provider = provider_for(&idp);
        let (_dir, store) = store();

        let missing = idp.signed_xml_with("alice@example.com", REQUEST_ID, |r| {
            r.assertion.as_mut().unwrap().conditions = None;
        });
        let err = post(&provider, &store, &missing).unwrap_err().to_string();
        assert!(err.contains("audience"), "{err}");

        let other = idp.signed_xml_with("alice@example.com", REQUEST_ID, |r| {
            let conditions = r.assertion.as_mut().unwrap().conditions.as_mut().unwrap();
            let restrictions = conditions.audience_restrictions.as_mut().unwrap();
            restrictions.push(samael::schema::AudienceRestriction {
                audience: vec!["https://other-sp.example.com".to_string()],
            });
        });
        let err = post(&provider, &store, &other).unwrap_err().to_string();
        assert!(err.contains("audience"), "{err}");
    }

    /// Many IdPs sign only the assertion, not the response around it.
    #[test]
    fn a_response_with_only_the_assertion_signed_is_accepted() {
        let idp = Idp::new();
        let provider = provider_for(&idp);
        let (_dir, store) = store();

        let xml = idp.signed_assertion_xml("alice@example.com", REQUEST_ID);
        let assertion = post(&provider, &store, &xml).expect("assertion-signed response");
        assert_eq!(assertion.user_id, "alice@example.com");

        // The unsigned response around it cannot change who is logged in.
        let xml = idp.signed_assertion_xml("alice@example.com", "_req-second");
        provider.remember_request("_req-second");
        let tampered = xml.replace("alice@example.com", "admin@example.com");
        assert!(post(&provider, &store, &tampered).is_err());
    }

    /// The response with a DOCTYPE carried in an encoding the `<!DOCTYPE`
    /// text check cannot see: UTF-7 (declared) and UTF-16BE (detected from
    /// the first bytes; ASCII in UTF-16BE is valid UTF-8 with NULs).
    fn with_hidden_doctype(signed: &str) -> Vec<(&'static str, String)> {
        let body = signed.split_once("?>").map_or(signed, |(_, b)| b);
        let utf7 = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-7\"?>\
             +ADw-!DOCTYPE r +AFs-+ADw-!ENTITY x 'y'+AD4-+AF0-+AD4-{}",
            body.replace('+', "+-")
        );
        let plain = format!("<!DOCTYPE r [<!ENTITY x 'y'>]>{body}");
        let utf16: String = plain
            .chars()
            .flat_map(|c| {
                assert!(c.is_ascii());
                ['\0', c]
            })
            .collect();
        vec![("utf-7", utf7), ("utf-16be", utf16)]
    }

    /// The structural checks refuse a DTD; that must not depend on the
    /// encoding the document is written in.
    #[test]
    fn a_doctype_in_another_encoding_is_rejected() {
        let idp = Idp::new();
        let provider = provider_for(&idp);
        let (_dir, store) = store();

        let signed = idp.signed_xml("alice@example.com", REQUEST_ID);
        for (encoding, xml) in with_hidden_doctype(&signed) {
            assert!(!xml.contains("<!DOCTYPE"), "{encoding}");
            match post(&provider, &store, &xml) {
                Ok(a) => panic!("{encoding}: response with a DTD accepted for {}", a.user_id),
                Err(e) => assert!(
                    e.to_string().contains("DTD") || e.to_string().contains("encoding"),
                    "{encoding}: {e}"
                ),
            }
        }
    }
}
