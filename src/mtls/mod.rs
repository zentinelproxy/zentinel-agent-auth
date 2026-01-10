//! mTLS client certificate authentication.
//!
//! Authenticates clients using X.509 certificates passed from the proxy
//! after TLS termination.

pub mod config;
pub mod validator;

pub use config::{MtlsConfig, MtlsConfigJson};
pub use validator::{validate_client_cert, CertificateInfo, MtlsIdentity};
