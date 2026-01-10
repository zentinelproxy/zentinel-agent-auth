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
│ JWKS Cache lookup   │──── kid not found ────┐
│ Get DecodingKey     │                       │
└─────────┬───────────┘                       ▼
          │                          ┌─────────────────┐
          │                          │ Refresh JWKS    │
          │                          │ from jwks_url   │
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
| `jwks-refresh-secs` | int | `3600` | How often to refresh JWKS cache |
| `clock-skew-secs` | int | `30` | Tolerance for clock differences |

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

## JWKS Key Rotation

The agent handles key rotation automatically:

1. Keys are cached in memory
2. Cache is refreshed every `jwks-refresh-secs` (default: 1 hour)
3. If a token references an unknown `kid`, cache is immediately refreshed
4. Both RSA and EC keys are supported

### Supported Algorithms

- **RSA**: RS256, RS384, RS512
- **EC**: ES256, ES384, ES512

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

1. The IdP may have rotated keys - agent will auto-refresh
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
