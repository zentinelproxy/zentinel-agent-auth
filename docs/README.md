# Sentinel Auth Agent Documentation

This directory contains documentation for the Sentinel Authentication Agent.

## Contents

| Document | Description |
|----------|-------------|
| [Configuration Reference](configuration.md) | Complete configuration options for all auth methods |
| [SAML Authentication](saml.md) | SAML SSO setup and IdP integration guide |
| [Session Management](session-management.md) | Session persistence and lifecycle |

## Quick Links

- [Main README](../README.md) - Installation and basic usage
- [GitHub Repository](https://github.com/raskell-io/sentinel-agent-auth)
- [Sentinel Proxy](https://github.com/raskell-io/sentinel)

## Authentication Methods

The agent supports four authentication methods:

1. **JWT/Bearer Tokens** - Industry-standard JSON Web Tokens with HS256, RS256, ES256
2. **API Keys** - Simple header-based authentication for service-to-service calls
3. **Basic Auth** - Username/password authentication (RFC 7617)
4. **SAML SSO** - Enterprise single sign-on with session persistence

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
                    │  │ JWT/API/   │  │
                    │  │ Basic Auth │  │
                    │  └────────────┘  │
                    │  ┌────────────┐  │
                    │  │ SAML SSO   │  │
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

## Getting Help

- Check the [configuration reference](configuration.md) for all options
- See [SAML guide](saml.md) for IdP-specific setup
- File issues at [GitHub Issues](https://github.com/raskell-io/sentinel-agent-auth/issues)
