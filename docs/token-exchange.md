# Token Exchange (RFC 8693)

The auth agent supports OAuth 2.0 Token Exchange as defined in [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693). This enables exchanging one token type for another.

## Overview

Token exchange is useful for:
- Converting SAML assertions to JWTs for API access
- Exchanging external IdP tokens for internal tokens
- Obtaining tokens with different audiences or scopes
- Impersonation and delegation scenarios

## How It Works

```
POST /token/exchange
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<saml_assertion_or_jwt>
&subject_token_type=urn:ietf:params:oauth:token-type:saml2
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
         │
         ▼
┌─────────────────────┐
│ Validate subject    │
│ token               │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Extract identity    │
│ and claims          │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Issue new token     │
│ with requested type │
└─────────┬───────────┘
          │
          ▼
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

## Configuration

### Basic Setup

```kdl
agents {
    agent "auth" {
        config {
            token-exchange {
                enabled true
                endpoint-path "/token/exchange"
                issuer "https://auth.internal.example.com"
                signing-key-file "/etc/zentinel/jwt-private.pem"
                signing-algorithm "RS256"
            }
        }
    }
}
```

### Full Configuration

```json
{
  "token-exchange": {
    "enabled": true,
    "endpoint-path": "/token/exchange",
    "issuer": "https://auth.internal.example.com",
    "signing-key-file": "/etc/zentinel/jwt-private.pem",
    "signing-algorithm": "RS256",
    "default-audience": "internal-api",
    "token-ttl-secs": 3600,
    "allowed-exchanges": [
      {
        "subject-token-type": "saml2",
        "issued-token-type": "access_token"
      },
      {
        "subject-token-type": "jwt",
        "issued-token-type": "access_token"
      }
    ]
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable token exchange |
| `endpoint-path` | string | `/token/exchange` | Path for exchange endpoint |
| `issuer` | string | - | Issuer for new tokens (required) |
| `signing-key-file` | string | - | Path to signing key (required) |
| `signing-algorithm` | string | `RS256` | Signing algorithm |
| `default-audience` | string | - | Default audience for issued tokens |
| `token-ttl-secs` | int | `3600` | Token lifetime |
| `allowed-exchanges` | array | `[]` | Allowed conversions |

## Token Types

Standard token type URIs:

| Token Type | URI |
|------------|-----|
| Access Token | `urn:ietf:params:oauth:token-type:access_token` |
| ID Token | `urn:ietf:params:oauth:token-type:id_token` |
| SAML 2.0 | `urn:ietf:params:oauth:token-type:saml2` |
| JWT | `urn:ietf:params:oauth:token-type:jwt` |
| Refresh Token | `urn:ietf:params:oauth:token-type:refresh_token` |

## Request Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `grant_type` | Yes | Must be `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | Yes | The token to exchange |
| `subject_token_type` | Yes | Type of the subject token |
| `requested_token_type` | No | Desired token type (default: access_token) |
| `audience` | No | Intended audience for new token |
| `scope` | No | Requested scopes |
| `resource` | No | Resource indicator |

## Response

Successful exchange:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

Error response:

```json
{
  "error": "invalid_grant",
  "error_description": "Subject token validation failed"
}
```

## Use Cases

### SAML to JWT Exchange

Convert a SAML assertion from an IdP into a JWT for API access:

```bash
# Get SAML assertion (base64 encoded)
SAML_ASSERTION=$(base64 -w0 saml-response.xml)

# Exchange for JWT
curl -X POST http://localhost:8080/token/exchange \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$SAML_ASSERTION" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:saml2" \
  -d "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=my-api"
```

### External to Internal JWT

Exchange an external IdP token for an internal token:

```bash
# External token from Auth0, Okta, etc.
EXTERNAL_TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Exchange for internal token
curl -X POST http://localhost:8080/token/exchange \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$EXTERNAL_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  -d "audience=internal-api"
```

### Audience Switching

Get a token for a different service:

```bash
# Token for service A
TOKEN_A="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Exchange for token with service B audience
curl -X POST http://localhost:8080/token/exchange \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$TOKEN_A" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=service-b"
```

## Issued Token Claims

The exchanged token includes:

| Claim | Description | Example |
|-------|-------------|---------|
| `iss` | Token issuer (from config) | `https://auth.internal.example.com` |
| `sub` | Subject from original token | `user@example.com` |
| `aud` | Requested audience | `my-api` |
| `exp` | Expiration time | Unix timestamp |
| `iat` | Issued at | Unix timestamp |
| `nbf` | Not before | Unix timestamp |
| `jti` | Unique token ID | UUID |
| `act` | Actor claim (for delegation) | Original subject |
| `scope` | Granted scopes | `read write` |

## Restricting Exchanges

Use `allowed-exchanges` to control which conversions are permitted:

```json
{
  "token-exchange": {
    "allowed-exchanges": [
      {
        "subject-token-type": "saml2",
        "issued-token-type": "access_token"
      }
    ]
  }
}
```

This configuration only allows SAML to access token exchanges.

## Signing Keys

### RSA Keys (RS256)

Generate an RSA key pair:

```bash
# Generate private key
openssl genrsa -out jwt-private.pem 2048

# Extract public key
openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem
```

Configure:

```json
{
  "token-exchange": {
    "signing-key-file": "/etc/zentinel/jwt-private.pem",
    "signing-algorithm": "RS256"
  }
}
```

### EC Keys (ES256)

Generate an EC key pair:

```bash
# Generate private key
openssl ecparam -genkey -name prime256v1 -out jwt-private.pem

# Extract public key
openssl ec -in jwt-private.pem -pubout -out jwt-public.pem
```

Configure:

```json
{
  "token-exchange": {
    "signing-key-file": "/etc/zentinel/jwt-private.pem",
    "signing-algorithm": "ES256"
  }
}
```

### HMAC Keys (HS256)

For symmetric signing (not recommended for production):

```json
{
  "token-exchange": {
    "signing-key": "your-secret-key-at-least-32-characters",
    "signing-algorithm": "HS256"
  }
}
```

## Error Handling

| Error | Description |
|-------|-------------|
| `invalid_request` | Missing required parameter |
| `invalid_grant` | Subject token validation failed |
| `unsupported_token_type` | Token type not supported |
| `invalid_target` | Invalid audience or resource |

## Integration Example

Python client:

```python
import requests

def exchange_token(subject_token, subject_type, audience):
    response = requests.post(
        "http://auth-agent/token/exchange",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": f"urn:ietf:params:oauth:token-type:{subject_type}",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": audience,
        }
    )
    response.raise_for_status()
    return response.json()["access_token"]

# Exchange SAML for JWT
jwt = exchange_token(saml_assertion, "saml2", "my-api")

# Use the JWT
headers = {"Authorization": f"Bearer {jwt}"}
requests.get("http://api/resource", headers=headers)
```

## Security Considerations

1. **Protect signing keys** - Use secure storage (HSM, vault)
2. **Rate limit** the exchange endpoint to prevent abuse
3. **Validate subject tokens** thoroughly before issuing
4. **Use short TTLs** for exchanged tokens
5. **Audit all exchanges** for security monitoring
6. **Restrict allowed exchanges** to necessary conversions
7. **Use asymmetric keys** (RS256, ES256) in production
8. **Validate audiences** to prevent token misuse
