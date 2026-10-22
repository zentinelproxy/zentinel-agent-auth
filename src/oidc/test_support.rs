//! Test fixtures: a local JWKS endpoint and tokens signed with a test key.
//!
//! The RSA key pair in `testdata/` exists only for these tests.

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::config::OidcConfig;

pub const TEST_ISSUER: &str = "https://issuer.test";
pub const TEST_KID: &str = "test-rsa";
pub const TEST_RSA_PRIVATE_PEM: &str = include_str!("testdata/test_rsa_private.key");
pub const TEST_RSA_PUBLIC_PEM: &str = include_str!("testdata/test_rsa_public.key");
pub const TEST_RSA_N: &str = include_str!("testdata/test_rsa_n.txt");

/// JWKS with the test key, declared as RS256.
pub fn test_jwks() -> String {
    serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "kid": TEST_KID,
            "alg": "RS256",
            "use": "sig",
            "n": TEST_RSA_N.trim(),
            "e": "AQAB"
        }]
    })
    .to_string()
}

/// A local HTTP server answering every request with a JWKS document.
pub struct JwksServer {
    addr: std::net::SocketAddr,
    hits: Arc<AtomicU64>,
}

impl JwksServer {
    pub async fn start() -> Self {
        Self::start_with(test_jwks(), false).await
    }

    /// A server that accepts connections and never answers.
    pub async fn start_hanging() -> Self {
        Self::start_with(String::new(), true).await
    }

    pub async fn start_with(body: String, hang: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let mut read = Vec::new();
                    while !read.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => read.extend_from_slice(&buf[..n]),
                        }
                    }
                    if hang {
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                        return;
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { addr, hits }
    }

    pub fn url(&self) -> String {
        format!("http://{}/jwks.json", self.addr)
    }

    /// Number of connections (one per fetch) the server accepted.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::SeqCst)
    }
}

/// An enabled OIDC config for the test issuer and `jwks_url`.
pub fn test_oidc_config(jwks_url: &str) -> OidcConfig {
    OidcConfig {
        enabled: true,
        issuer: TEST_ISSUER.to_string(),
        jwks_url: jwks_url.to_string(),
        ..OidcConfig::default()
    }
}

/// Claims for a valid token from the test issuer, plus `extra`.
pub fn test_claims(sub: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut claims = serde_json::json!({
        "sub": sub,
        "iss": TEST_ISSUER,
        "exp": chrono::Utc::now().timestamp() + 600,
    });
    if let (Some(map), Some(extra)) = (claims.as_object_mut(), extra.as_object()) {
        for (k, v) in extra {
            map.insert(k.clone(), v.clone());
        }
    }
    claims
}

/// Sign `claims` with the test RSA key.
pub fn sign_rsa(alg: Algorithm, kid: Option<&str>, claims: &serde_json::Value) -> String {
    let mut header = Header::new(alg);
    header.kid = kid.map(String::from);
    let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_PEM.as_bytes()).unwrap();
    encode(&header, claims, &key).unwrap()
}

/// Sign `claims` with HS256, using the test RSA *public key* as the HMAC
/// secret: the classic algorithm-confusion forgery.
pub fn forge_hs256_with_public_key(kid: Option<&str>, claims: &serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = kid.map(String::from);
    let key = EncodingKey::from_secret(TEST_RSA_PUBLIC_PEM.as_bytes());
    encode(&header, claims, &key).unwrap()
}

/// An unsigned token (`alg: none`), built by hand since the JWT library
/// refuses to produce one.
pub fn unsigned_token(kid: Option<&str>, claims: &serde_json::Value) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let mut header = serde_json::json!({ "alg": "none", "typ": "JWT" });
    if let Some(kid) = kid {
        header["kid"] = serde_json::json!(kid);
    }
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}
