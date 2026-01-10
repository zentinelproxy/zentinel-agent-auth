# Sentinel Auth Agent Documentation

This directory contains documentation for the Sentinel Authentication and Authorization Agent.

## Contents

| Document | Description |
|----------|-------------|
| [Configuration Reference](configuration.md) | Complete configuration options for all auth methods |
| [SAML Authentication](saml.md) | SAML SSO setup and IdP integration guide |
| [Session Management](session-management.md) | Session persistence and lifecycle |
| [OIDC Authentication](oidc.md) | OIDC/OAuth 2.0 with JWKS auto-refresh |
| [mTLS Authentication](mtls.md) | Client certificate authentication |
| [Authorization](authorization.md) | Cedar policy engine guide |
| [Token Exchange](token-exchange.md) | RFC 8693 token exchange |

## Quick Links

- [Main README](../README.md) - Installation and basic usage
- [GitHub Repository](https://github.com/raskell-io/sentinel-agent-auth)
- [Sentinel Proxy](https://github.com/raskell-io/sentinel)

## Authentication Methods

The agent supports six authentication methods:

1. **JWT/Bearer Tokens** - Industry-standard JSON Web Tokens with HS256, RS256, ES256
2. **OIDC/OAuth 2.0** - OpenID Connect with automatic JWKS key rotation
3. **API Keys** - Simple header-based authentication for service-to-service calls
4. **Basic Auth** - Username/password authentication (RFC 7617)
5. **SAML SSO** - Enterprise single sign-on with session persistence
6. **mTLS Client Certificates** - X.509 certificate-based authentication for zero-trust

## Authorization

The agent supports policy-based authorization using the Cedar Policy Engine:

- **Cedar Policies** - Define fine-grained access control with principal/action/resource model
- **Default deny** - Secure by default with explicit allow policies

## Token Services

- **Token Exchange (RFC 8693)** - Convert between token types (SAML→JWT, external→internal JWT)

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────┐
│   Client    │────▶│  Sentinel Proxy  │────▶│   Upstream   │
└─────────────┘     └────────┬─────────┘     └──────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │   Auth Agent     │
                    │  ┌────────────┐  │
                    │  │ AuthN      │  │
                    │  │ JWT/OIDC/  │  │
                    │  │ mTLS/SAML  │  │
                    │  └────────────┘  │
                    │  ┌────────────┐  │
                    │  │ AuthZ      │  │
                    │  │ Cedar      │  │
                    │  └────────────┘  │
                    │  ┌────────────┐  │
                    │  │ Token      │  │
                    │  │ Exchange   │  │
                    │  └────────────┘  │
                    │  ┌────────────┐  │
                    │  │ Session    │  │
                    │  │ Store      │  │
                    │  └────────────┘  │
                    └──────────────────┘
```

## Request Flow

### JWT/API Key/Basic Auth

1. Client sends request with credentials (Authorization header or API key)
2. Sentinel forwards request headers to auth agent
3. Agent validates credentials
4. On success: adds identity headers, allows request
5. On failure: returns 401 Unauthorized

### SAML SSO

1. Client sends request without session cookie
2. Agent redirects to IdP with SAML AuthnRequest
3. User authenticates at IdP
4. IdP posts SAML Response to ACS endpoint
5. Agent validates assertion, creates session, sets cookie
6. Client retries with session cookie
7. Agent validates session, adds identity headers

### OIDC/OAuth 2.0

1. Client sends request with OAuth 2.0 Bearer token
2. Agent extracts `kid` from JWT header
3. Agent looks up signing key in JWKS cache (refreshes if needed)
4. Agent validates token signature, issuer, audience, expiry
5. On success: adds identity headers with claims, allows request
6. On failure: returns 401 Unauthorized

### mTLS Client Certificates

1. Client connects with TLS client certificate
2. Sentinel proxy terminates TLS, extracts certificate
3. Proxy forwards certificate in `X-Client-Cert` header
4. Agent parses certificate, checks DN/SAN allowlists
5. On success: adds identity headers (CN as user ID), allows request
6. On failure: returns 401 Unauthorized

### Authorization (Cedar)

After authentication:

1. Agent builds Cedar request (principal, action, resource, context)
2. Cedar evaluates policies against request
3. If allowed: request proceeds to upstream
4. If denied: returns 403 Forbidden with policy reason

## Getting Help

- Check the [configuration reference](configuration.md) for all options
- See [SAML guide](saml.md) for IdP-specific setup
- File issues at [GitHub Issues](https://github.com/raskell-io/sentinel-agent-auth/issues)
