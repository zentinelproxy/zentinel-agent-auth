# sentinel-agent-auth

Authentication agent for [Sentinel](https://github.com/raskell-io/sentinel) reverse proxy. Supports JWT/Bearer tokens, API keys, Basic authentication, and SAML SSO.

## Features

- **JWT/Bearer tokens** - HS256, RS256, ES256 and other algorithms
- **API keys** - Simple header-based authentication
- **Basic auth** - Username/password authentication
- **SAML SSO** - Enterprise single sign-on with session persistence
- Configurable user ID and auth method headers
- Fail-open mode for graceful degradation

## Documentation

- [Configuration Reference](docs/configuration.md) - Complete configuration options
- [SAML Authentication](docs/saml.md) - SAML SSO setup and IdP integration
- [Session Management](docs/session-management.md) - Session persistence and lifecycle

## Installation

### From crates.io

```bash
cargo install sentinel-agent-auth
```

### From source

```bash
git clone https://github.com/raskell-io/sentinel-agent-auth
cd sentinel-agent-auth
cargo build --release
```

## Usage

```bash
sentinel-auth-agent --socket /var/run/sentinel/auth.sock \
  --jwt-secret "your-secret-key" \
  --api-keys "key1:app1,key2:app2"
```

### Command Line Options

| Option | Environment Variable | Description | Default |
|--------|---------------------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/sentinel-auth.sock` |
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

## Authentication Methods

### JWT/Bearer Token

```bash
# Configure with HS256 secret
sentinel-auth-agent --jwt-secret "your-32-char-minimum-secret-key"

# Configure with RS256 public key
sentinel-auth-agent --jwt-algorithm RS256 --jwt-public-key /path/to/public.pem

# With issuer and audience validation
sentinel-auth-agent \
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
sentinel-auth-agent --api-keys "sk_live_abc123:production,sk_test_xyz:development"
```

Client request:
```bash
curl -H "X-API-Key: sk_live_abc123" http://localhost:8080/api
```

### Basic Auth

```bash
# Configure users
sentinel-auth-agent --basic-auth-users "admin:secretpass,user:userpass"
```

Client request:
```bash
curl -u "admin:secretpass" http://localhost:8080/api
```

## Headers Added

On successful authentication, the agent adds these headers to the request:

| Header | Description | Example |
|--------|-------------|---------|
| `X-User-Id` | Authenticated user ID | `user123` |
| `X-Auth-Method` | Authentication method used | `jwt`, `api_key`, `basic` |
| `X-Auth-Claim-*` | JWT claims (for JWT auth) | `X-Auth-Claim-role: admin` |

## Configuration

### Sentinel Proxy Configuration

```kdl
agents {
    agent "auth" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/sentinel/auth.sock"
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

The agent adds `WWW-Authenticate: Bearer realm="sentinel"` header on 401 responses.

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

- Always use strong, random JWT secrets (minimum 32 characters for HS256)
- Store secrets in environment variables, not command line args
- Use RS256/ES256 with public keys for production when possible
- Enable `fail_open` cautiously - only for non-critical paths
- Consider rate limiting alongside authentication

## License

Apache-2.0
