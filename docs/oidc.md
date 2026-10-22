# OIDC/OAuth 2.0 Authentication

The auth agent supports OpenID Connect (OIDC) and OAuth 2.0 token validation with automatic JWKS (JSON Web Key Set) key rotation.

## Overview

OIDC authentication validates Bearer tokens issued by external identity providers like Auth0, Okta, Azure AD, or Keycloak. The agent automatically fetches and caches signing keys from the provider's JWKS endpoint.

## How It Works

```
Client with OAuth token
         │
         ▼
┌─────────────────────┐
│ Parse JWT header    │
│ Extract 'kid'       │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Check 'alg' against │
│ the allowlist       │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ JWKS Cache lookup   │──── kid not found ────┐
│ Get DecodingKey     │                       │
└─────────┬───────────┘                       ▼
          │                          ┌─────────────────┐
          │                          │ Refresh JWKS    │
          │                          │ (at most once   │
          │                          │ per interval)   │
          │                          └────────┬────────┘
          │                                   │
          ▼◀──────────────────────────────────┘
┌─────────────────────┐
│ Validate signature  │
│ Check iss, aud, exp │
│ Check scopes        │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Return Identity     │
│ method: oidc        │
└─────────────────────┘
```

## Configuration

### Basic Setup

```kdl
agents {
    agent "auth" {
        config {
            oidc {
                enabled true
                issuer "https://auth.example.com"
                jwks-url "https://auth.example.com/.well-known/jwks.json"
                audience "my-api"
            }
        }
    }
}
```

### Full Configuration

```json
{
  "oidc": {
    "enabled": true,
    "issuer": "https://auth.example.com",
    "jwks-url": "https://auth.example.com/.well-known/jwks.json",
    "audience": "my-api",
    "required-scopes": ["read", "write"],
    "jwks-refresh-secs": 3600,
    "jwks-min-refetch-secs": 60,
    "jwks-fetch-timeout-ms": 5000,
    "allowed-algorithms": ["RS256"],
    "clock-skew-secs": 30
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable OIDC authentication |
| `issuer` | string | - | Expected `iss` claim in tokens (required) |
| `jwks-url` | string | - | URL to fetch JWKS (required) |
| `audience` | string | - | Expected `aud` claim |
| `required-scopes` | array | `[]` | Scopes that must be present in token |
| `jwks-refresh-secs` | int | `3600` | How often to refresh JWKS cache (in the background) |
| `jwks-min-refetch-secs` | int | `60` | Minimum time between two JWKS fetches; must be at least 1 |
| `jwks-fetch-timeout-ms` | int | `5000` | Timeout for one JWKS fetch (1 to 30000) |
| `allowed-algorithms` | array | `[]` | Signature algorithms tokens may use. Empty: the algorithms the JWKS keys declare. `none` and `HS*` are rejected |
| `clock-skew-secs` | int | `30` | Tolerance for clock differences |
| `user-id-claim` | string | `sub` | Claim used as the user ID |
| `scope-claim` | string | `scope` | Claim holding the token's scopes |

A configuration that fails validation (for example `allowed-algorithms`
naming `HS256`) is rejected whole: `on_configure` returns false and nothing
of it is applied.

## Identity Provider Setup

### Auth0

```json
{
  "oidc": {
    "enabled": true,
    "issuer": "https://your-tenant.auth0.com/",
    "jwks-url": "https://your-tenant.auth0.com/.well-known/jwks.json",
    "audience": "https://your-api.example.com"
  }
}
```

### Okta

```json
{
  "oidc": {
    "enabled": true,
    "issuer": "https://your-org.okta.com/oauth2/default",
    "jwks-url": "https://your-org.okta.com/oauth2/default/v1/keys",
    "audience": "api://your-api"
  }
}
```

### Azure AD

```json
{
  "oidc": {
    "enabled": true,
    "issuer": "https://login.microsoftonline.com/{tenant-id}/v2.0",
    "jwks-url": "https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys",
    "audience": "api://{client-id}"
  }
}
```

### Keycloak

```json
{
  "oidc": {
    "enabled": true,
    "issuer": "https://keycloak.example.com/realms/your-realm",
    "jwks-url": "https://keycloak.example.com/realms/your-realm/protocol/openid-connect/certs",
    "audience": "your-client-id"
  }
}
```

## Scope Validation

To require specific scopes:

```json
{
  "oidc": {
    "enabled": true,
    "issuer": "https://auth.example.com",
    "jwks-url": "https://auth.example.com/.well-known/jwks.json",
    "required-scopes": ["read:users", "write:users"]
  }
}
```

Tokens must include ALL required scopes in the `scope` claim.

## Headers Added

On successful OIDC authentication:

| Header | Description | Example |
|--------|-------------|---------|
| `X-User-Id` | Subject claim (`sub`) | `auth0|123456` |
| `X-Auth-Method` | Authentication method | `oidc` |
| `X-Auth-Claim-sub` | Subject | `auth0|123456` |
| `X-Auth-Claim-email` | Email (if present) | `user@example.com` |
| `X-Auth-Claim-scope` | Token scopes | `read write` |

All standard and custom claims are forwarded as `X-Auth-Claim-{name}` headers.

## Signature Algorithms

The `alg` in a token header is chosen by whoever made the token, so the agent
does not let it pick how the token is verified:

1. `alg` must be in `allowed-algorithms`. When that list is empty, it must be
   one of the algorithms the JWKS keys declare in their `alg` field; a key
   that declares none counts as `RS256` (RSA), `ES256` (P-256) or `ES384`
   (P-384).
2. The key must accept it. A key that declares an `alg` verifies only that
   algorithm. A key that declares none verifies only algorithms of its type:
   RS*/PS* for RSA, ES256 for P-256, ES384 for P-384. List PS256 (say) in
   `allowed-algorithms` to accept PS256 tokens from an RSA key that declares
   no `alg`.
3. `none` (unsigned) and `HS256`/`HS384`/`HS512` are never accepted: with a
   public key as the HMAC secret, anyone holding the public key could sign
   tokens (algorithm confusion). Listing them in `allowed-algorithms` rejects
   the configuration, and JWKS keys that declare them are skipped.

A token without a `kid` is tried against every key that accepts its `alg`.

### Supported Algorithms

- **RSA**: RS256, RS384, RS512, PS256, PS384, PS512
- **EC**: ES256 (P-256), ES384 (P-384)

## JWKS Fetching and Key Rotation

1. Configuring OIDC never waits for the JWKS endpoint: the keys are fetched
   in the background, and tokens are rejected until they have loaded.
2. Every fetch is bounded by `jwks-fetch-timeout-ms` (default 5 s).
3. Keys are refreshed in the background once they are `jwks-refresh-secs`
   old (default 1 hour); requests keep using the cached keys meanwhile.
4. A token whose `kid` is not cached triggers a refetch, but at most one
   fetch starts per `jwks-min-refetch-secs` (default 60 s), and concurrent
   misses wait for that one fetch. A `kid` that a fetch did not return is
   remembered as unknown until the next fetch, so a flood of tokens with
   made-up `kid`s costs the IdP one request per interval. Failed fetches
   count against the interval too.
5. After an IdP rotates its keys, tokens signed with the new key are accepted
   once a fetch has picked it up: at the latest after
   `jwks-min-refetch-secs`.

The `oidc_jwks_fetches_total` metric counts fetches.

## Client Usage

```bash
# Get token from your IdP
TOKEN=$(curl -s -X POST "https://auth.example.com/oauth/token" \
  -d "client_id=xxx" \
  -d "client_secret=yyy" \
  -d "grant_type=client_credentials" \
  -d "audience=my-api" | jq -r '.access_token')

# Use token
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/resource
```

## Troubleshooting

### Token Validation Fails

1. **Check issuer**: Ensure `issuer` config matches the `iss` claim exactly (including trailing slashes)
2. **Check audience**: Verify `audience` matches the `aud` claim
3. **Check JWKS URL**: Verify the URL is accessible from the agent
4. **Check clock sync**: Token may be expired or not yet valid

### Key Not Found

If you see "Key with kid 'xxx' not found":

1. The IdP may have rotated keys - the agent refetches, at most once per
   `jwks-min-refetch-secs`
2. Check that the JWKS URL returns the correct key set
3. Verify network connectivity to the JWKS endpoint

### Scope Validation Fails

Ensure the token includes all required scopes. Check the token's `scope` claim matches your configuration.

## Security Considerations

1. **Always use HTTPS** for JWKS endpoints
2. **Validate issuer** to prevent token confusion attacks
3. **Validate audience** to ensure tokens are intended for your API
4. **Use short-lived tokens** (5-15 minutes) when possible
5. **Rotate JWKS frequently** at the IdP level
6. **Pin `allowed-algorithms`** to what your IdP signs with (often just
   `RS256`), rather than relying on what the JWKS declares
