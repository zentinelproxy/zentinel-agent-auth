//! JWKS (JSON Web Key Set) fetching and caching.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// JWKS cache with automatic refresh.
pub struct JwksCache {
    /// Cached keys: kid -> DecodingKey
    keys: RwLock<HashMap<String, CachedKey>>,
    /// Last refresh timestamp
    last_refresh: RwLock<Instant>,
    /// Refresh interval
    refresh_interval: Duration,
    /// JWKS endpoint URL
    jwks_url: String,
    /// HTTP client
    http_client: reqwest::Client,
}

struct CachedKey {
    key: DecodingKey,
    #[allow(dead_code)]
    alg: Option<String>,
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

impl JwksCache {
    /// Create a new JWKS cache.
    pub async fn new(jwks_url: String, refresh_secs: u64) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("Failed to create HTTP client")?;

        let cache = Self {
            keys: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(Instant::now() - Duration::from_secs(refresh_secs + 1)),
            refresh_interval: Duration::from_secs(refresh_secs),
            jwks_url,
            http_client,
        };

        // Initial fetch
        cache.refresh().await?;

        Ok(cache)
    }

    /// Get a decoding key by key ID.
    /// If the key is not found, attempts to refresh the cache.
    pub async fn get_key(&self, kid: &str) -> Result<DecodingKey> {
        // Check cache first
        {
            let keys = self.keys.read().map_err(|_| anyhow!("Lock poisoned"))?;
            if let Some(cached) = keys.get(kid) {
                return Ok(cached.key.clone());
            }
        }

        // Key not found, try refreshing
        debug!(kid = %kid, "Key not found in cache, refreshing JWKS");
        self.refresh().await?;

        // Check again after refresh
        let keys = self.keys.read().map_err(|_| anyhow!("Lock poisoned"))?;
        keys.get(kid)
            .map(|c| c.key.clone())
            .ok_or_else(|| anyhow!("Key with kid '{}' not found in JWKS", kid))
    }

    /// Get a decoding key when no kid is specified.
    /// Returns the first suitable key for signing.
    pub async fn get_default_key(&self) -> Result<DecodingKey> {
        // Ensure cache is fresh
        self.refresh_if_needed().await?;

        let keys = self.keys.read().map_err(|_| anyhow!("Lock poisoned"))?;

        // Return any key marked for signing, or the first key
        keys.values()
            .next()
            .map(|c| c.key.clone())
            .ok_or_else(|| anyhow!("No keys available in JWKS"))
    }

    /// Refresh the cache if the refresh interval has elapsed.
    pub async fn refresh_if_needed(&self) -> Result<()> {
        let should_refresh = {
            let last = self.last_refresh.read().map_err(|_| anyhow!("Lock poisoned"))?;
            last.elapsed() >= self.refresh_interval
        };

        if should_refresh {
            self.refresh().await?;
        }

        Ok(())
    }

    /// Force refresh the JWKS cache.
    pub async fn refresh(&self) -> Result<()> {
        debug!(url = %self.jwks_url, "Fetching JWKS");

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

        let mut new_keys = HashMap::new();
        for jwk in jwks.keys {
            // Skip encryption keys
            if jwk.key_use.as_deref() == Some("enc") {
                continue;
            }

            match Self::jwk_to_decoding_key(&jwk) {
                Ok(key) => {
                    let kid = jwk.kid.clone().unwrap_or_else(|| "default".to_string());
                    new_keys.insert(
                        kid.clone(),
                        CachedKey {
                            key,
                            alg: jwk.alg.clone(),
                        },
                    );
                    debug!(kid = %kid, kty = %jwk.kty, "Loaded JWK");
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

        if new_keys.is_empty() {
            return Err(anyhow!("No valid signing keys found in JWKS"));
        }

        // Update cache
        {
            let mut keys = self.keys.write().map_err(|_| anyhow!("Lock poisoned"))?;
            *keys = new_keys;
        }

        {
            let mut last = self
                .last_refresh
                .write()
                .map_err(|_| anyhow!("Lock poisoned"))?;
            *last = Instant::now();
        }

        info!(
            url = %self.jwks_url,
            key_count = self.keys.read().map(|k| k.len()).unwrap_or(0),
            "JWKS cache refreshed"
        );

        Ok(())
    }

    /// Convert a JWK to a DecodingKey.
    fn jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey> {
        match jwk.kty.as_str() {
            "RSA" => {
                let n = jwk.n.as_ref().ok_or_else(|| anyhow!("RSA key missing 'n'"))?;
                let e = jwk.e.as_ref().ok_or_else(|| anyhow!("RSA key missing 'e'"))?;

                DecodingKey::from_rsa_components(n, e)
                    .context("Failed to create RSA DecodingKey")
            }
            "EC" => {
                let x = jwk.x.as_ref().ok_or_else(|| anyhow!("EC key missing 'x'"))?;
                let y = jwk.y.as_ref().ok_or_else(|| anyhow!("EC key missing 'y'"))?;
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

        let key = JwksCache::jwk_to_decoding_key(&jwk);
        assert!(key.is_ok());
    }
}
