//! JWKS (JSON Web Key Set) fetching and caching.
//!
//! Fetches never happen on the configure path: [`JwksCache::new`] only builds
//! the cache, and [`JwksCache::spawn_refresh`] loads it in the background.
//! Every fetch has a bounded timeout, and fetches are rate-limited: however
//! many tokens arrive with an unknown `kid`, the endpoint is fetched at most
//! once per `min_refetch_interval`.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use super::config::parse_asymmetric_algorithm;

/// At most this many unknown key IDs are remembered between fetches.
const MAX_UNKNOWN_KIDS: usize = 1024;

/// Timing settings for a [`JwksCache`].
#[derive(Debug, Clone, Copy)]
pub struct JwksSettings {
    /// Refresh the keys in the background once they are this old.
    pub refresh_interval: Duration,
    /// Never fetch the endpoint more often than this.
    pub min_refetch_interval: Duration,
    /// Timeout for one fetch.
    pub fetch_timeout: Duration,
}

/// The kind of public key, which fixes the algorithms it can verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Rsa,
    EcP256,
    EcP384,
}

impl KeyKind {
    fn from_jwk(jwk: &Jwk) -> Result<Self> {
        match (jwk.kty.as_str(), jwk.crv.as_deref()) {
            ("RSA", _) => Ok(KeyKind::Rsa),
            ("EC", Some("P-256")) => Ok(KeyKind::EcP256),
            ("EC", Some("P-384")) => Ok(KeyKind::EcP384),
            ("EC", crv) => Err(anyhow!("Unsupported EC curve: {:?}", crv)),
            (kty, _) => Err(anyhow!("Unsupported key type: {}", kty)),
        }
    }

    /// Whether a key of this kind can verify `alg` at all.
    pub fn supports(self, alg: Algorithm) -> bool {
        match self {
            KeyKind::Rsa => matches!(
                alg,
                Algorithm::RS256
                    | Algorithm::RS384
                    | Algorithm::RS512
                    | Algorithm::PS256
                    | Algorithm::PS384
                    | Algorithm::PS512
            ),
            KeyKind::EcP256 => alg == Algorithm::ES256,
            KeyKind::EcP384 => alg == Algorithm::ES384,
        }
    }

    /// The algorithm assumed for a key that declares none.
    fn default_algorithm(self) -> Algorithm {
        match self {
            KeyKind::Rsa => Algorithm::RS256,
            KeyKind::EcP256 => Algorithm::ES256,
            KeyKind::EcP384 => Algorithm::ES384,
        }
    }
}

/// A verified-usable public key from the JWKS.
#[derive(Clone)]
pub struct CachedKey {
    pub key: DecodingKey,
    pub kind: KeyKind,
    /// The `alg` the JWK declares, if any. A declared algorithm binds the
    /// key: a token naming any other algorithm is not verified with it.
    pub declared_alg: Option<Algorithm>,
}

impl CachedKey {
    /// Whether a token signed with `alg` may be verified with this key.
    pub fn accepts(&self, alg: Algorithm) -> bool {
        match self.declared_alg {
            Some(declared) => declared == alg,
            None => self.kind.supports(alg),
        }
    }

    /// The algorithm this key advertises for the default allowlist.
    fn advertised_algorithm(&self) -> Algorithm {
        self.declared_alg
            .unwrap_or_else(|| self.kind.default_algorithm())
    }
}

#[derive(Default)]
struct KeySet {
    by_kid: HashMap<String, CachedKey>,
    all: Vec<CachedKey>,
}

/// JWKS cache with rate-limited, bounded fetching.
pub struct JwksCache {
    keys: RwLock<KeySet>,
    /// When the keys were last loaded successfully.
    last_success: RwLock<Option<Instant>>,
    /// When a fetch was last started, successful or not.
    last_attempt: RwLock<Option<Instant>>,
    /// Key IDs a fetch did not return, and when they were found missing.
    unknown_kids: RwLock<HashMap<String, Instant>>,
    /// Serializes fetches, so concurrent misses wait for one fetch.
    fetch_lock: tokio::sync::Mutex<()>,
    settings: JwksSettings,
    jwks_url: String,
    http_client: reqwest::Client,
    fetches: AtomicU64,
}

/// JWKS response from the endpoint.
#[derive(Debug, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Individual JSON Web Key.
#[derive(Debug, Deserialize)]
pub struct Jwk {
    /// Key type (RSA, EC)
    pub kty: String,
    /// Key ID
    pub kid: Option<String>,
    /// Algorithm
    pub alg: Option<String>,
    /// Key use (sig, enc)
    #[serde(rename = "use")]
    pub key_use: Option<String>,

    // RSA parameters
    /// RSA modulus (base64url)
    pub n: Option<String>,
    /// RSA exponent (base64url)
    pub e: Option<String>,

    // EC parameters
    /// EC curve
    pub crv: Option<String>,
    /// EC x coordinate (base64url)
    pub x: Option<String>,
    /// EC y coordinate (base64url)
    pub y: Option<String>,
}

fn lock_err<T>(_: T) -> anyhow::Error {
    anyhow!("JWKS cache lock poisoned")
}

impl JwksCache {
    /// Create an empty JWKS cache. Nothing is fetched here; call
    /// [`JwksCache::spawn_refresh`] to load the keys in the background.
    pub fn new(jwks_url: String, settings: JwksSettings) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(settings.fetch_timeout)
            .connect_timeout(settings.fetch_timeout)
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            keys: RwLock::new(KeySet::default()),
            last_success: RwLock::new(None),
            last_attempt: RwLock::new(None),
            unknown_kids: RwLock::new(HashMap::new()),
            fetch_lock: tokio::sync::Mutex::new(()),
            settings,
            jwks_url,
            http_client,
            fetches: AtomicU64::new(0),
        })
    }

    /// Fetch the keys in a background task (rate-limited). Without a Tokio
    /// runtime nothing is spawned and the first token loads the keys.
    pub fn spawn_refresh(self: &Arc<Self>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let this = Arc::clone(self);
        handle.spawn(async move {
            if let Err(e) = this.refresh_rate_limited().await {
                warn!(url = %this.jwks_url, error = %e, "JWKS fetch failed");
            }
        });
    }

    /// Number of fetches started so far.
    pub fn fetch_count(&self) -> u64 {
        self.fetches.load(Ordering::Relaxed)
    }

    /// The algorithms the loaded keys declare (or imply, for keys that
    /// declare none). Never contains `none` or an `HS*` algorithm.
    pub fn advertised_algorithms(&self) -> HashSet<Algorithm> {
        self.keys
            .read()
            .map(|k| k.all.iter().map(|c| c.advertised_algorithm()).collect())
            .unwrap_or_default()
    }

    /// Get the key for `kid`. An unknown `kid` triggers at most one fetch per
    /// `min_refetch_interval`; until then it is answered from the
    /// remembered-unknown list without waiting.
    pub async fn get_key(self: &Arc<Self>, kid: &str) -> Result<CachedKey> {
        self.refresh_in_background_if_stale();

        if let Some(key) = self.lookup(kid)? {
            return Ok(key);
        }
        if self.recently_unknown(kid)? {
            return Err(anyhow!("Key with kid '{}' not found in JWKS", kid));
        }

        debug!(kid = %kid, "Key not found in cache, refreshing JWKS");
        let fetched = self.refresh_rate_limited().await;

        if let Some(key) = self.lookup(kid)? {
            return Ok(key);
        }
        self.remember_unknown(kid)?;
        fetched?;
        Err(anyhow!("Key with kid '{}' not found in JWKS", kid))
    }

    /// Keys that may verify a token without a `kid` that is signed with
    /// `alg`.
    pub async fn candidate_keys(self: &Arc<Self>, alg: Algorithm) -> Result<Vec<CachedKey>> {
        self.refresh_in_background_if_stale();

        if self.keys.read().map_err(lock_err)?.all.is_empty() {
            self.refresh_rate_limited().await?;
        }

        let keys = self.keys.read().map_err(lock_err)?;
        let candidates: Vec<CachedKey> = keys
            .all
            .iter()
            .filter(|k| k.accepts(alg))
            .cloned()
            .collect();
        if candidates.is_empty() {
            return Err(anyhow!("No JWKS key accepts algorithm {:?}", alg));
        }
        Ok(candidates)
    }

    fn lookup(&self, kid: &str) -> Result<Option<CachedKey>> {
        Ok(self.keys.read().map_err(lock_err)?.by_kid.get(kid).cloned())
    }

    fn recently_unknown(&self, kid: &str) -> Result<bool> {
        let unknown = self.unknown_kids.read().map_err(lock_err)?;
        Ok(unknown
            .get(kid)
            .is_some_and(|t| t.elapsed() < self.settings.min_refetch_interval))
    }

    fn remember_unknown(&self, kid: &str) -> Result<()> {
        let mut unknown = self.unknown_kids.write().map_err(lock_err)?;
        let window = self.settings.min_refetch_interval;
        unknown.retain(|_, t| t.elapsed() < window);
        if unknown.len() < MAX_UNKNOWN_KIDS {
            unknown.insert(kid.to_string(), Instant::now());
        }
        Ok(())
    }

    fn refresh_in_background_if_stale(self: &Arc<Self>) {
        let stale = match self.last_success.read() {
            Ok(last) => last.is_some_and(|t| t.elapsed() >= self.settings.refresh_interval),
            Err(_) => false,
        };
        let may_fetch = match self.last_attempt.read() {
            Ok(last) => last.is_none_or(|t| t.elapsed() >= self.settings.min_refetch_interval),
            Err(_) => false,
        };
        if stale && may_fetch {
            self.spawn_refresh();
        }
    }

    /// Fetch the JWKS unless a fetch started less than `min_refetch_interval`
    /// ago. Returns whether a fetch ran. Concurrent callers wait for the
    /// running fetch instead of starting their own.
    pub async fn refresh_rate_limited(&self) -> Result<bool> {
        let _guard = self.fetch_lock.lock().await;
        {
            let mut last = self.last_attempt.write().map_err(lock_err)?;
            if last.is_some_and(|t| t.elapsed() < self.settings.min_refetch_interval) {
                return Ok(false);
            }
            *last = Some(Instant::now());
        }
        self.fetch_and_store().await?;
        Ok(true)
    }

    /// Fetch the JWKS and replace the cached keys.
    async fn fetch_and_store(&self) -> Result<()> {
        debug!(url = %self.jwks_url, "Fetching JWKS");
        self.fetches.fetch_add(1, Ordering::Relaxed);

        let response = self
            .http_client
            .get(&self.jwks_url)
            .send()
            .await
            .context("Failed to fetch JWKS")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "JWKS endpoint returned status {}",
                response.status()
            ));
        }

        let jwks: Jwks = response.json().await.context("Failed to parse JWKS")?;

        let mut new_keys = KeySet::default();
        for jwk in jwks.keys {
            // Skip encryption keys
            if jwk.key_use.as_deref() == Some("enc") {
                continue;
            }

            match Self::parse_jwk(&jwk) {
                Ok(cached) => {
                    debug!(kid = ?jwk.kid, kty = %jwk.kty, "Loaded JWK");
                    if let Some(kid) = jwk.kid.clone() {
                        new_keys.by_kid.insert(kid, cached.clone());
                    }
                    new_keys.all.push(cached);
                }
                Err(e) => {
                    warn!(
                        kid = ?jwk.kid,
                        kty = %jwk.kty,
                        error = %e,
                        "Failed to parse JWK, skipping"
                    );
                }
            }
        }

        if new_keys.all.is_empty() {
            return Err(anyhow!("No valid signing keys found in JWKS"));
        }

        let key_count = new_keys.all.len();
        *self.keys.write().map_err(lock_err)? = new_keys;
        *self.last_success.write().map_err(lock_err)? = Some(Instant::now());
        self.unknown_kids.write().map_err(lock_err)?.clear();

        info!(url = %self.jwks_url, key_count, "JWKS cache refreshed");
        Ok(())
    }

    /// Build a cached key from a JWK, binding it to its declared algorithm.
    fn parse_jwk(jwk: &Jwk) -> Result<CachedKey> {
        let kind = KeyKind::from_jwk(jwk)?;
        let declared_alg = match jwk.alg.as_deref() {
            None => None,
            Some(name) => {
                let alg = parse_asymmetric_algorithm(name).map_err(|e| anyhow!(e))?;
                if !kind.supports(alg) {
                    return Err(anyhow!(
                        "JWK declares {name}, which a {kind:?} key cannot use"
                    ));
                }
                Some(alg)
            }
        };
        Ok(CachedKey {
            key: Self::jwk_to_decoding_key(jwk)?,
            kind,
            declared_alg,
        })
    }

    /// Convert a JWK to a DecodingKey.
    fn jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey> {
        match jwk.kty.as_str() {
            "RSA" => {
                let n = jwk
                    .n
                    .as_ref()
                    .ok_or_else(|| anyhow!("RSA key missing 'n'"))?;
                let e = jwk
                    .e
                    .as_ref()
                    .ok_or_else(|| anyhow!("RSA key missing 'e'"))?;

                DecodingKey::from_rsa_components(n, e).context("Failed to create RSA DecodingKey")
            }
            "EC" => {
                let x = jwk
                    .x
                    .as_ref()
                    .ok_or_else(|| anyhow!("EC key missing 'x'"))?;
                let y = jwk
                    .y
                    .as_ref()
                    .ok_or_else(|| anyhow!("EC key missing 'y'"))?;
                let crv = jwk
                    .crv
                    .as_ref()
                    .ok_or_else(|| anyhow!("EC key missing 'crv'"))?;

                // Decode x and y from base64url
                let x_bytes = URL_SAFE_NO_PAD
                    .decode(x)
                    .context("Failed to decode EC x coordinate")?;
                let y_bytes = URL_SAFE_NO_PAD
                    .decode(y)
                    .context("Failed to decode EC y coordinate")?;

                // Build uncompressed EC point (0x04 || x || y)
                let mut point = vec![0x04];
                point.extend_from_slice(&x_bytes);
                point.extend_from_slice(&y_bytes);

                // Create key based on curve
                match crv.as_str() {
                    "P-256" => {
                        let der = Self::wrap_ec_public_key(&point, crv)?;
                        Ok(DecodingKey::from_ec_der(&der))
                    }
                    "P-384" => {
                        let der = Self::wrap_ec_public_key(&point, crv)?;
                        Ok(DecodingKey::from_ec_der(&der))
                    }
                    _ => Err(anyhow!("Unsupported EC curve: {}", crv)),
                }
            }
            kty => Err(anyhow!("Unsupported key type: {}", kty)),
        }
    }

    /// Wrap EC public key point in DER format.
    fn wrap_ec_public_key(point: &[u8], curve: &str) -> Result<Vec<u8>> {
        // OID for EC public key
        let ec_public_key_oid = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

        // Curve OID
        let curve_oid: &[u8] = match curve {
            "P-256" => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
            "P-384" => &[0x2B, 0x81, 0x04, 0x00, 0x22],
            _ => return Err(anyhow!("Unsupported curve for DER encoding: {}", curve)),
        };

        // Build AlgorithmIdentifier sequence
        let mut alg_id = vec![0x30]; // SEQUENCE
        let alg_id_content_len = 2 + ec_public_key_oid.len() + 2 + curve_oid.len();
        alg_id.push(alg_id_content_len as u8);
        alg_id.push(0x06); // OID tag
        alg_id.push(ec_public_key_oid.len() as u8);
        alg_id.extend_from_slice(ec_public_key_oid);
        alg_id.push(0x06); // OID tag
        alg_id.push(curve_oid.len() as u8);
        alg_id.extend_from_slice(curve_oid);

        // Build BIT STRING for public key
        let mut bit_string = vec![0x03]; // BIT STRING tag
        let bit_string_len = point.len() + 1; // +1 for unused bits byte
        if bit_string_len < 128 {
            bit_string.push(bit_string_len as u8);
        } else {
            bit_string.push(0x81);
            bit_string.push(bit_string_len as u8);
        }
        bit_string.push(0x00); // unused bits
        bit_string.extend_from_slice(point);

        // Build outer SEQUENCE
        let mut der = vec![0x30]; // SEQUENCE
        let total_len = alg_id.len() + bit_string.len();
        if total_len < 128 {
            der.push(total_len as u8);
        } else {
            der.push(0x81);
            der.push(total_len as u8);
        }
        der.extend_from_slice(&alg_id);
        der.extend_from_slice(&bit_string);

        Ok(der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::test_support::JwksServer;

    fn settings(min_refetch_secs: u64) -> JwksSettings {
        JwksSettings {
            refresh_interval: Duration::from_secs(3600),
            min_refetch_interval: Duration::from_secs(min_refetch_secs),
            fetch_timeout: Duration::from_millis(2000),
        }
    }

    #[test]
    fn test_jwk_parsing() {
        let jwk_json = r#"{
            "kty": "RSA",
            "kid": "test-key-1",
            "alg": "RS256",
            "use": "sig",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        }"#;

        let jwk: Jwk = serde_json::from_str(jwk_json).unwrap();
        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.kid, Some("test-key-1".to_string()));
        assert_eq!(jwk.alg, Some("RS256".to_string()));

        let key = JwksCache::parse_jwk(&jwk).unwrap();
        assert_eq!(key.declared_alg, Some(Algorithm::RS256));
        assert!(key.accepts(Algorithm::RS256));
        assert!(!key.accepts(Algorithm::PS256));
        assert!(!key.accepts(Algorithm::HS256));
    }

    #[test]
    fn symmetric_and_mismatched_jwks_are_skipped() {
        let hs: Jwk =
            serde_json::from_str(r#"{"kty":"RSA","alg":"HS256","n":"AQAB","e":"AQAB"}"#).unwrap();
        assert!(JwksCache::parse_jwk(&hs).is_err());
        let oct: Jwk = serde_json::from_str(r#"{"kty":"oct","alg":"HS256"}"#).unwrap();
        assert!(JwksCache::parse_jwk(&oct).is_err());
        let ec_rs: Jwk =
            serde_json::from_str(r#"{"kty":"EC","crv":"P-256","alg":"RS256","x":"AA","y":"AA"}"#)
                .unwrap();
        assert!(JwksCache::parse_jwk(&ec_rs).is_err());
    }

    #[tokio::test]
    async fn new_does_not_fetch() {
        let server = JwksServer::start().await;
        let cache = JwksCache::new(server.url(), settings(60)).unwrap();
        assert_eq!(cache.fetch_count(), 0);
        assert_eq!(server.hits(), 0);
    }

    #[tokio::test]
    async fn an_unknown_kid_flood_fetches_the_jwks_once_per_interval() {
        let server = JwksServer::start().await;
        let cache = Arc::new(JwksCache::new(server.url(), settings(60)).unwrap());

        // The known key loads with the first lookup.
        assert!(cache.get_key("test-rsa").await.is_ok());
        assert_eq!(server.hits(), 1);

        // 200 tokens with distinct unknown kids, concurrently and serially.
        let mut tasks = Vec::new();
        for i in 0..100 {
            let cache = Arc::clone(&cache);
            tasks.push(tokio::spawn(async move {
                cache.get_key(&format!("forged-{i}")).await
            }));
        }
        for t in tasks {
            assert!(t.await.unwrap().is_err());
        }
        for i in 100..200 {
            assert!(cache.get_key(&format!("forged-{i}")).await.is_err());
        }
        // A repeated unknown kid is answered from the negative cache.
        assert!(cache.get_key("forged-7").await.is_err());

        assert_eq!(
            server.hits(),
            1,
            "an unknown kid inside the refetch interval must not refetch"
        );
        // Known keys keep working.
        assert!(cache.get_key("test-rsa").await.is_ok());
    }

    #[tokio::test]
    async fn an_unknown_kid_refetches_again_after_the_interval() {
        let server = JwksServer::start().await;
        let cache = Arc::new(JwksCache::new(server.url(), settings(1)).unwrap());
        assert!(cache.get_key("rotated").await.is_err());
        assert_eq!(server.hits(), 1);
        assert!(cache.get_key("rotated").await.is_err());
        assert_eq!(server.hits(), 1);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(cache.get_key("rotated").await.is_err());
        assert_eq!(server.hits(), 2);
    }

    #[tokio::test]
    async fn a_hanging_jwks_endpoint_is_bounded_by_the_timeout() {
        let server = JwksServer::start_hanging().await;
        let cache = Arc::new(
            JwksCache::new(
                server.url(),
                JwksSettings {
                    fetch_timeout: Duration::from_millis(200),
                    ..settings(60)
                },
            )
            .unwrap(),
        );
        let started = Instant::now();
        assert!(cache.get_key("any").await.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        // And the failed fetch counts against the rate limit.
        assert!(cache.get_key("other").await.is_err());
        assert_eq!(cache.fetch_count(), 1);
    }
}
