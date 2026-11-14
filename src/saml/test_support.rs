//! A test IdP that signs real SAML responses (libxmlsec1, exclusive c14n).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Duration, Utc};
use samael::idp::{
    response_builder::build_response_template, CertificateParams, IdentityProvider, KeyType, Rsa,
};
use samael::schema::Response;
use samael::traits::ToXml;

pub(crate) const SP_ENTITY: &str = "https://sp.example.com";
pub(crate) const ACS_URL: &str = "https://sp.example.com/saml/acs";
pub(crate) const IDP_ENTITY: &str = "https://idp.example.com";

pub(crate) struct Idp {
    idp: IdentityProvider,
    cert_der: Vec<u8>,
}

impl Idp {
    pub(crate) fn new() -> Self {
        let idp = IdentityProvider::generate_new(KeyType::Rsa(Rsa::Rsa2048)).unwrap();
        let cert_der = idp
            .create_certificate(&CertificateParams {
                common_name: "idp.example.com",
                issuer_name: "idp.example.com",
                days_until_expiration: 30,
            })
            .unwrap();
        Self { idp, cert_der }
    }

    pub(crate) fn cert_pem(&self) -> String {
        let b64 = BASE64.encode(&self.cert_der);
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            lines.join("\n")
        )
    }

    /// The response template the IdP would sign, for `name_id`.
    pub(crate) fn template(&self, name_id: &str, request_id: &str) -> Response {
        let mut response = build_response_template(
            &self.cert_der,
            name_id,
            SP_ENTITY,
            IDP_ENTITY,
            ACS_URL,
            request_id,
            &[],
        );
        let assertion = response.assertion.as_mut().unwrap();
        let data = assertion
            .subject
            .as_mut()
            .unwrap()
            .subject_confirmations
            .as_mut()
            .unwrap()[0]
            .subject_confirmation_data
            .as_mut()
            .unwrap();
        data.not_on_or_after = Some(Utc::now() + Duration::minutes(5));
        response
    }

    /// A response signed with exclusive c14n by libxmlsec1, as XML.
    pub(crate) fn signed_xml(&self, name_id: &str, request_id: &str) -> String {
        let unsigned = self.template(name_id, request_id).to_string().unwrap();
        samael::crypto::sign_xml(unsigned, &self.idp.export_private_key_der().unwrap()).unwrap()
    }
}
