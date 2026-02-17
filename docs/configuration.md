# Configuration Reference

The auth agent can be configured via command-line arguments, environment variables, or dynamic configuration from the Zentinel proxy.

## Command-Line Options

### Socket Configuration

| Option | Environment | Description | Default |
|--------|-------------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/zentinel-auth.sock` |

### JWT Configuration

| Option | Environment | Description | Default |
|--------|-------------|-------------|---------|
| `--jwt-secret` | `JWT_SECRET` | Secret key for HS256 | - |
| `--jwt-public-key` | `JWT_PUBLIC_KEY` | Public key file for RS256/ES256 | - |
| `--jwt-algorithm` | `JWT_ALGORITHM` | Algorithm (HS256, RS256, ES256) | `HS256` |
| `--jwt-issuer` | `JWT_ISSUER` | Required issuer claim | - |
| `--jwt-audience` | `JWT_AUDIENCE` | Required audience claim | - |

### API Key Configuration

| Option | Environment | Description | Default |
|--------|-------------|-------------|---------|
| `--api-keys` | `API_KEYS` | API keys as `key:name,key:name` | - |
| `--api-key-header` | `API_KEY_HEADER` | Header name for API key | `X-API-Key` |

### Basic Auth Configuration

| Option | Environment | Description | Default |
|--------|-------------|-------------|---------|
| `--basic-auth-users` | `BASIC_AUTH_USERS` | Users as `user:pass,user:pass` | - |

### Output Headers

| Option | Environment | Description | Default |
|--------|-------------|-------------|---------|
| `--user-id-header` | `USER_ID_HEADER` | Header for authenticated user ID | `X-User-Id` |
| `--auth-method-header` | `AUTH_METHOD_HEADER` | Header for auth method used | `X-Auth-Method` |

### Behavior

| Option | Environment | Description | Default |
|--------|-------------|-------------|---------|
| `--fail-open` | `FAIL_OPEN` | Allow requests on auth failure | `false` |
| `--verbose` | `AUTH_VERBOSE` | Enable debug logging | `false` |

## Dynamic Configuration (JSON)

The agent supports runtime reconfiguration via Zentinel's `on_configure` event. Configuration is sent as JSON in the agent config block.

### Zentinel Proxy Configuration

```kdl
agents {
    agent "auth" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/zentinel/auth.sock"
        }
        events ["request_headers" "request_body_chunk"]
        timeout-ms 100
        failure-mode "closed"

        config {
            // JWT configuration
            jwt-secret "your-secret-key-at-least-32-chars"
            jwt-algorithm "HS256"
            jwt-issuer "https://auth.example.com"
            jwt-audience "my-api"

            // API keys
            api-keys "sk_live_abc123:production,sk_test_xyz:staging"
            api-key-header "X-API-Key"

            // Basic auth
            basic-auth-users "admin:secret,readonly:password"

            // Output headers
            user-id-header "X-User-Id"
            auth-method-header "X-Auth-Method"

            // Behavior
            fail-open false

            // SAML configuration (see saml.md for details)
            saml {
                enabled true
                entity-id "https://app.example.com/sp"
                acs-url "https://app.example.com/saml/acs"
                idp-sso-url "https://idp.example.com/sso"
                idp-entity-id "https://idp.example.com"
                session-ttl-secs 28800
            }
        }
    }
}
```

### JSON Configuration Schema

```json
{
  "jwt-secret": "string",
  "jwt-public-key": "string (PEM)",
  "jwt-algorithm": "HS256 | RS256 | ES256",
  "jwt-issuer": "string",
  "jwt-audience": "string",
  "api-keys": "key:name,key:name",
  "api-key-header": "string",
  "basic-auth-users": "user:pass,user:pass",
  "user-id-header": "string",
  "auth-method-header": "string",
  "fail-open": "boolean",
  "saml": {
    "enabled": "boolean",
    "entity-id": "string",
    "acs-url": "string",
    "...": "see SAML configuration"
  }
}
```

## SAML Configuration

See [SAML Authentication](saml.md) for complete SAML configuration options.

### Quick Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable SAML authentication |
| `entity-id` | string | - | SP entity ID (required) |
| `acs-url` | string | - | Assertion Consumer Service URL (required) |
| `acs-path` | string | `/saml/acs` | Path to match for ACS endpoint |
| `idp-sso-url` | string | - | IdP SSO endpoint |
| `idp-entity-id` | string | - | IdP entity ID |
| `idp-metadata-url` | string | - | URL to fetch IdP metadata |
| `session-ttl-secs` | int | `28800` | Session lifetime (8 hours) |
| `session-store-path` | string | `/var/lib/zentinel-auth/sessions.redb` | Session database path |

## OIDC Configuration

OpenID Connect / OAuth 2.0 authentication with automatic JWKS key rotation.

See [OIDC Authentication](oidc.md) for detailed setup guide.

### JSON Configuration

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

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable OIDC authentication |
| `issuer` | string | - | Expected token issuer (required) |
| `jwks-url` | string | - | URL to fetch JWKS (required) |
| `audience` | string | - | Expected audience claim |
| `required-scopes` | array | `[]` | Scopes that must be present |
| `jwks-refresh-secs` | int | `3600` | JWKS cache refresh interval |
| `clock-skew-secs` | int | `30` | Clock skew tolerance |

## mTLS Configuration

Client certificate authentication for zero-trust architectures.

See [mTLS Authentication](mtls.md) for detailed setup guide.

### JSON Configuration

```json
{
  "mtls": {
    "enabled": true,
    "client-cert-header": "X-Client-Cert",
    "ca-cert-path": "/etc/ssl/ca.crt",
    "allowed-dns": ["CN=service.example.com,O=Example Corp"],
    "allowed-sans": ["service@example.com"],
    "extract-cn-as-user": true,
    "extract-san-email-as-user": false,
    "log-certs": false
  }
}
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable mTLS authentication |
| `client-cert-header` | string | `X-Client-Cert` | Header containing client certificate |
| `ca-cert-path` | string | - | CA certificate for chain validation |
| `allowed-dns` | array | `[]` | Allowed Distinguished Names |
| `allowed-sans` | array | `[]` | Allowed Subject Alternative Names |
| `extract-cn-as-user` | bool | `true` | Use CN as user ID |
| `extract-san-email-as-user` | bool | `false` | Use SAN email as user ID |
| `log-certs` | bool | `false` | Log certificate details (debug) |

## Authorization Configuration

Cedar policy engine for fine-grained access control.

See [Authorization](authorization.md) for policy writing guide.

### JSON Configuration

```json
{
  "authz": {
    "enabled": true,
    "policy-file": "/etc/zentinel/policies/auth.cedar",
    "default-decision": "deny",
    "principal-claim": "sub",
    "roles-claim": "roles"
  }
}
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable authorization |
| `policy-file` | string | - | Path to Cedar policy file |
| `policy-inline` | string | - | Inline Cedar policy text |
| `default-decision` | string | `deny` | Decision when no policy matches (`allow` or `deny`) |
| `principal-claim` | string | `sub` | JWT claim for principal ID |
| `roles-claim` | string | - | JWT claim containing roles array |

## Token Exchange Configuration

RFC 8693 token exchange endpoint for converting between token types.

See [Token Exchange](token-exchange.md) for detailed guide.

### JSON Configuration

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

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable token exchange endpoint |
| `endpoint-path` | string | `/token/exchange` | Path for exchange endpoint |
| `issuer` | string | - | Issuer for exchanged tokens (required) |
| `signing-key-file` | string | - | Path to signing key (required) |
| `signing-algorithm` | string | `RS256` | Algorithm for signing (`RS256`, `ES256`, `HS256`) |
| `default-audience` | string | - | Default audience for issued tokens |
| `token-ttl-secs` | int | `3600` | Token lifetime in seconds |
| `allowed-exchanges` | array | `[]` | Allowed token type conversions |

## Environment Variable Examples

```bash
# JWT with HS256
export JWT_SECRET="your-secret-key-minimum-32-characters"
export JWT_ISSUER="https://auth.example.com"
export JWT_AUDIENCE="my-api"

# JWT with RS256
export JWT_ALGORITHM="RS256"
export JWT_PUBLIC_KEY="/etc/zentinel/jwt-public.pem"

# API Keys
export API_KEYS="sk_live_abc123:production,sk_test_xyz:development"

# Basic Auth
export BASIC_AUTH_USERS="admin:supersecret,readonly:readpass"

# Headers
export USER_ID_HEADER="X-User-Id"
export AUTH_METHOD_HEADER="X-Auth-Method"

# Socket
export AGENT_SOCKET="/var/run/zentinel/auth.sock"
```

## Headers Added to Requests

On successful authentication, the agent adds these headers:

| Header | Description | Auth Methods |
|--------|-------------|--------------|
| `X-User-Id` | Authenticated user identifier | All |
| `X-Auth-Method` | Method used (`jwt`, `api_key`, `basic`, `saml`) | All |
| `X-Auth-Claim-{name}` | JWT claims (flattened) | JWT |
| Custom attribute headers | SAML attributes via `attribute-mapping` | SAML |

### JWT Claim Headers

For JWT authentication, claims are added as headers with the `X-Auth-Claim-` prefix:

```
JWT payload: {"sub": "user123", "role": "admin", "org_id": "acme"}

Headers added:
X-User-Id: user123
X-Auth-Method: jwt
X-Auth-Claim-sub: user123
X-Auth-Claim-role: admin
X-Auth-Claim-org_id: acme
```

### SAML Attribute Headers

For SAML, use `attribute-mapping` to map SAML attributes to headers:

```json
{
  "saml": {
    "attribute-mapping": {
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "X-Auth-Email",
      "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups": "X-Auth-Groups"
    }
  }
}
```

## Precedence

When multiple auth methods are configured, they are checked in this order:

1. **mTLS Client Certificate** - if `X-Client-Cert` header present
2. **Session cookie** (SAML) - if present and valid
3. **Authorization: Bearer** (OIDC) - if OIDC configured and header present
4. **Authorization: Bearer** (JWT) - if JWT configured and header present
5. **API Key header** - if configured header present
6. **Authorization: Basic** - if header present

The first successful authentication wins. If all methods fail, the agent returns 401 (or allows the request if `fail-open` is true).

After authentication, if authorization is enabled, the Cedar policy engine evaluates the request. A 403 Forbidden is returned if the policy denies access.

## Security Recommendations

1. **Use environment variables** for secrets, not command-line arguments
2. **Use RS256/ES256** for JWT in production (asymmetric keys)
3. **Set `fail-open: false`** for security-critical routes
4. **Use HTTPS** for all SAML and OIDC endpoints (required by spec)
5. **Rotate secrets** regularly (JWT secrets, API keys, signing keys)
6. **Limit session TTL** based on security requirements
7. **Use default deny** for Cedar authorization policies
8. **Validate JWKS sources** - only configure trusted issuer URLs
9. **Use CA validation** for mTLS when possible
10. **Rate limit token exchange** endpoint to prevent abuse
