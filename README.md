# zentinel-agent-auth

Authentication and authorization agent for [Zentinel](https://github.com/zentinelproxy/zentinel) reverse proxy. Supports JWT/Bearer tokens, OIDC/OAuth 2.0, API keys, Basic authentication, SAML SSO, and mTLS client certificates.

## Features

### Authentication (AuthN)
- **JWT/Bearer tokens** - HS256, RS256, ES256 and other algorithms
- **OIDC/OAuth 2.0** - OpenID Connect with automatic JWKS key rotation
- **API keys** - Simple header-based authentication
- **Basic auth** - Username/password authentication
- **SAML SSO** - Enterprise single sign-on with session persistence
- **mTLS Client Certificates** - X.509 certificate-based authentication

### Authorization (AuthZ)
- **Cedar Policy Engine** - Basic policy-as-code authorization (principal, action, resource evaluation)

### Token Services
- **Token Exchange (RFC 8693)** - Convert between token types (SAML to JWT, external to internal JWT)

### General
- Configurable user ID and auth method headers
- Fail-open mode for graceful degradation
- Comprehensive audit logging

## Documentation

- [Configuration Reference](docs/configuration.md) - Complete configuration options
- [SAML Authentication](docs/saml.md) - SAML SSO setup and IdP integration
- [Session Management](docs/session-management.md) - Session persistence and lifecycle
- [OIDC Authentication](docs/oidc.md) - OIDC/OAuth 2.0 with JWKS
- [mTLS Authentication](docs/mtls.md) - Client certificate authentication
- [Authorization](docs/authorization.md) - Cedar policy engine guide
- [Token Exchange](docs/token-exchange.md) - RFC 8693 token exchange

## Installation

### From crates.io

```bash
cargo install zentinel-agent-auth
```

### From source

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-auth
cd zentinel-agent-auth
cargo build --release
```

## Usage

```bash
zentinel-auth-agent --socket /var/run/zentinel/auth.sock \
  --jwt-secret "your-secret-key" \
  --api-keys "key1:app1,key2:app2"
```

### Command Line Options

| Option | Environment Variable | Description | Default |
|--------|---------------------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/zentinel-auth.sock` |
| `--jwt-secret` | `JWT_SECRET` | JWT secret key (for HS256) | - |
| `--jwt-public-key` | `JWT_PUBLIC_KEY` | JWT public key file (for RS/ES) | - |
| `--jwt-algorithm` | `JWT_ALGORITHM` | JWT algorithm | `HS256` |
| `--jwt-issuer` | `JWT_ISSUER` | Required JWT issuer | - |
| `--jwt-audience` | `JWT_AUDIENCE` | Required JWT audience | - |
| `--api-keys` | `API_KEYS` | API keys (key:name,key:name) | - |
| `--api-key-header` | `API_KEY_HEADER` | API key header name | `X-API-Key` |
| `--basic-auth-users` | `BASIC_AUTH_USERS` | Basic auth users (user:pass) | - |
| `--user-id-header` | `USER_ID_HEADER` | Header for user ID | `X-User-Id` |
| `--auth-method-header` | `AUTH_METHOD_HEADER` | Header for auth method | `X-Auth-Method` |
| `--fail-open` | `FAIL_OPEN` | Allow on auth failure | `false` |
| `--verbose` | `AUTH_VERBOSE` | Enable debug logging | `false` |

See [Configuration Reference](docs/configuration.md) for OIDC, mTLS, Cedar authorization, and token exchange options.

## Authentication Methods

### JWT/Bearer Token

```bash
# Configure with HS256 secret
zentinel-auth-agent --jwt-secret "your-32-char-minimum-secret-key"

# Configure with RS256 public key
zentinel-auth-agent --jwt-algorithm RS256 --jwt-public-key /path/to/public.pem

# With issuer and audience validation
zentinel-auth-agent \
  --jwt-secret "secret" \
  --jwt-issuer "https://auth.example.com" \
  --jwt-audience "my-api"
```

Client request:
```bash
curl -H "Authorization: Bearer eyJ..." http://localhost:8080/api
```

### API Key

```bash
# Configure API keys
zentinel-auth-agent --api-keys "sk_live_abc123:production,sk_test_xyz:development"
```

Client request:
```bash
curl -H "X-API-Key: sk_live_abc123" http://localhost:8080/api
```

### Basic Auth

```bash
# Configure users
zentinel-auth-agent --basic-auth-users "admin:secretpass,user:userpass"
```

Client request:
```bash
curl -u "admin:secretpass" http://localhost:8080/api
```

### OIDC/OAuth 2.0

Configure OIDC with automatic JWKS key fetching and refresh:

```kdl
config {
    oidc {
        enabled true
        issuer "https://auth.example.com"
        jwks-url "https://auth.example.com/.well-known/jwks.json"
        audience "my-api"
        required-scopes "read,write"
    }
}
```

Client request:
```bash
curl -H "Authorization: Bearer <oauth2-access-token>" http://localhost:8080/api
```

### mTLS Client Certificates

Authenticate clients using X.509 certificates (requires Zentinel proxy to forward client cert):

```kdl
config {
    mtls {
        enabled true
        client-cert-header "X-Client-Cert"
        allowed-dns "CN=service.example.com,O=Example"
        extract-cn-as-user true
    }
}
```

The Zentinel proxy forwards the client certificate in a header after TLS termination.

## Authorization

After authentication, requests can be authorized using Cedar policies:

```kdl
config {
    authz {
        enabled true
        policy-file "/etc/zentinel/policies/auth.cedar"
        default-decision "deny"
    }
}
```

Example Cedar policy:
```cedar
permit(
    principal,
    action == Action::"GET",
    resource
) when {
    resource.path like "/api/public/*"
};

permit(
    principal,
    action,
    resource
) when {
    principal.roles.contains("admin")
};
```

See [Authorization Guide](docs/authorization.md) for more details.

## Headers Added

On successful authentication, the agent adds these headers to the request:

| Header | Description | Example |
|--------|-------------|---------|
| `X-User-Id` | Authenticated user ID | `user123` |
| `X-Auth-Method` | Authentication method used | `jwt`, `oidc`, `mtls`, `api_key`, `basic`, `saml` |
| `X-Auth-Claim-*` | JWT/OIDC claims (for token auth) | `X-Auth-Claim-role: admin` |
| `X-Client-Cert-*` | Certificate info (for mTLS) | `X-Client-Cert-CN: service.example.com` |

## Configuration

### Zentinel Proxy Configuration

```kdl
agents {
    agent "auth" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/zentinel/auth.sock"
        }
        events ["request_headers"]
        timeout-ms 50
        failure-mode "open"
    }
}

routes {
    route "api" {
        matches { path-prefix "/api" }
        upstream "backend"
        agents ["auth"]
    }
}
```

### Docker/Kubernetes

```yaml
# Environment variables
JWT_SECRET: "your-secret-key"
JWT_ISSUER: "https://auth.example.com"
API_KEYS: "key1:app1,key2:app2"
FAIL_OPEN: "false"
```

## Response Codes

| Code | Description |
|------|-------------|
| 401 | No valid credentials provided |
| (passthrough) | Credentials valid, request forwarded |

The agent adds `WWW-Authenticate: Bearer realm="zentinel"` header on 401 responses.

## Development

```bash
# Run with debug logging
RUST_LOG=debug cargo run -- \
  --socket /tmp/test.sock \
  --jwt-secret "test-secret-at-least-32-characters" \
  --api-keys "test-key:test-app"

# Run tests
cargo test
```

## Security Considerations

- **Prefer RS256/ES256 over HS256 for JWT** — HS256 uses a shared secret (both signer and verifier must know it). Use asymmetric algorithms (RS256, ES256) in production to avoid sharing secrets across services.
- Always use strong, random JWT secrets (minimum 32 characters for HS256)
- Store secrets in environment variables, not command line args
- Use RS256/ES256 with public keys for production when possible
- Enable `fail_open` cautiously - only for non-critical paths
- Consider rate limiting alongside authentication

## License

Apache-2.0
