# SAML Authentication

This guide covers SAML 2.0 Single Sign-On (SSO) configuration for the Zentinel Auth Agent.

## Overview

The agent acts as a SAML Service Provider (SP), supporting SP-initiated SSO with any SAML 2.0 compliant Identity Provider (IdP).

### Supported Features

- SP-initiated SSO (redirect binding for AuthnRequest)
- POST binding for SAML Response
- Session persistence with embedded database (redb)
- Assertion replay prevention
- Clock skew tolerance
- Attribute mapping to headers
- Path-based protection rules

### Authentication Flow

```
┌────────┐     ┌─────────┐     ┌──────────┐     ┌─────┐
│ Client │     │ Zentinel│     │Auth Agent│     │ IdP │
└───┬────┘     └────┬────┘     └────┬─────┘     └──┬──┘
    │               │               │              │
    │ GET /app      │               │              │
    ├──────────────▶│               │              │
    │               │ Check auth    │              │
    │               ├──────────────▶│              │
    │               │               │              │
    │               │ No session    │              │
    │               │◀──────────────┤              │
    │               │               │              │
    │ 302 Redirect to IdP           │              │
    │◀──────────────┤               │              │
    │               │               │              │
    │ GET /sso?SAMLRequest=...      │              │
    ├──────────────────────────────────────────────▶
    │               │               │              │
    │         (User authenticates at IdP)          │
    │               │               │              │
    │ POST /saml/acs (SAMLResponse) │              │
    ├──────────────▶│               │              │
    │               │ Process ACS   │              │
    │               ├──────────────▶│              │
    │               │               │              │
    │               │ Session + Cookie             │
    │               │◀──────────────┤              │
    │               │               │              │
    │ 302 + Set-Cookie              │              │
    │◀──────────────┤               │              │
    │               │               │              │
    │ GET /app (with cookie)        │              │
    ├──────────────▶│               │              │
    │               │ Validate session             │
    │               ├──────────────▶│              │
    │               │               │              │
    │               │ Allow + headers              │
    │               │◀──────────────┤              │
    │               │               │              │
    │ 200 OK        │               │              │
    │◀──────────────┤               │              │
    └               └               └              └
```

## Configuration

### Minimal Configuration

```json
{
  "saml": {
    "enabled": true,
    "entity-id": "https://app.example.com/sp",
    "acs-url": "https://app.example.com/saml/acs",
    "idp-sso-url": "https://idp.example.com/sso",
    "idp-entity-id": "https://idp.example.com"
  }
}
```

### Complete Configuration Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| **Core Settings** |
| `enabled` | bool | `false` | Enable SAML authentication |
| `entity-id` | string | *required* | Unique identifier for this SP |
| `acs-url` | string | *required* | Full URL where IdP posts SAML Response |
| `acs-path` | string | `/saml/acs` | Path portion to match for ACS endpoint |
| `slo-url` | string | - | Single Logout Service URL (optional) |
| **IdP Configuration** |
| `idp-sso-url` | string | - | IdP SSO endpoint URL |
| `idp-entity-id` | string | - | IdP entity ID |
| `idp-metadata-url` | string | - | URL to fetch IdP metadata (alternative) |
| `idp-metadata-xml` | string | - | Inline IdP metadata XML (alternative) |
| `idp-certificate-pem` | string | - | IdP certificate for signature verification |
| **SP Certificates** |
| `private-key-pem` | string | - | SP private key for signing/decryption |
| `certificate-pem` | string | - | SP certificate for metadata |
| **Session Settings** |
| `session-ttl-secs` | int | `28800` | Session lifetime (default 8 hours) |
| `session-cookie-name` | string | `zentinel_saml_session` | Cookie name |
| `session-store-path` | string | `/var/lib/zentinel-auth/sessions.redb` | Database path |
| `cleanup-interval-secs` | int | `300` | Expired session cleanup interval |
| **Cookie Settings** |
| `cookie-domain` | string | - | Cookie domain (defaults to request host) |
| `cookie-path` | string | `/` | Cookie path |
| `cookie-secure` | bool | `true` | Require HTTPS (Secure flag) |
| `cookie-http-only` | bool | `true` | Prevent JavaScript access |
| `cookie-same-site` | string | `Lax` | SameSite policy |
| **Security Settings** |
| `allow-unsigned-assertions` | bool | `false` | Allow unsigned assertions (NOT recommended) |
| `clock-skew-secs` | int | `300` | Tolerance for clock differences (5 min) |
| **Path Protection** |
| `protected-paths` | array | `[]` | Paths to protect (empty = all) |
| `excluded-paths` | array | `[]` | Paths to exclude from protection |
| **Attribute Mapping** |
| `attribute-mapping` | object | `{}` | Map SAML attributes to headers |
| `name-id-format` | string | - | Requested NameID format |

## IdP Setup Guides

### Okta

1. Create a new SAML 2.0 application in Okta Admin Console
2. Configure SSO settings:
   - **Single Sign-On URL**: `https://app.example.com/saml/acs`
   - **Audience URI (SP Entity ID)**: `https://app.example.com/sp`
   - **Name ID format**: EmailAddress
3. Download IdP metadata or note the SSO URL and Entity ID
4. Configure the agent:

```json
{
  "saml": {
    "enabled": true,
    "entity-id": "https://app.example.com/sp",
    "acs-url": "https://app.example.com/saml/acs",
    "idp-metadata-url": "https://your-org.okta.com/app/exk.../sso/saml/metadata",
    "attribute-mapping": {
      "email": "X-Auth-Email",
      "firstName": "X-Auth-FirstName",
      "lastName": "X-Auth-LastName"
    }
  }
}
```

### Azure AD (Entra ID)

1. Register a new Enterprise Application
2. Set up SAML SSO:
   - **Identifier (Entity ID)**: `https://app.example.com/sp`
   - **Reply URL**: `https://app.example.com/saml/acs`
3. Download Federation Metadata XML
4. Configure attributes (Claims):
   - `emailaddress` → `user.mail`
   - `givenname` → `user.givenname`
   - `groups` → `user.groups`

```json
{
  "saml": {
    "enabled": true,
    "entity-id": "https://app.example.com/sp",
    "acs-url": "https://app.example.com/saml/acs",
    "idp-metadata-url": "https://login.microsoftonline.com/{tenant}/federationmetadata/2007-06/federationmetadata.xml",
    "attribute-mapping": {
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "X-Auth-Email",
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": "X-Auth-FirstName",
      "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups": "X-Auth-Groups"
    }
  }
}
```

### Google Workspace

1. Admin Console → Apps → Web and mobile apps → Add SAML app
2. Configure:
   - **ACS URL**: `https://app.example.com/saml/acs`
   - **Entity ID**: `https://app.example.com/sp`
   - **Name ID**: Basic Information > Primary Email
3. Download IdP metadata

```json
{
  "saml": {
    "enabled": true,
    "entity-id": "https://app.example.com/sp",
    "acs-url": "https://app.example.com/saml/acs",
    "idp-sso-url": "https://accounts.google.com/o/saml2/idp?idpid=...",
    "idp-entity-id": "https://accounts.google.com/o/saml2?idpid=...",
    "idp-certificate-pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }
}
```

### Keycloak

1. Create a new SAML client
2. Configure:
   - **Client ID**: `https://app.example.com/sp`
   - **Valid Redirect URIs**: `https://app.example.com/*`
   - **Master SAML Processing URL**: `https://app.example.com/saml/acs`
3. Map attributes in Client Scopes

```json
{
  "saml": {
    "enabled": true,
    "entity-id": "https://app.example.com/sp",
    "acs-url": "https://app.example.com/saml/acs",
    "idp-metadata-url": "https://keycloak.example.com/realms/myrealm/protocol/saml/descriptor"
  }
}
```

## Path Protection

### Protect All Paths (Default)

When `protected-paths` is empty, all paths are protected except those in `excluded-paths`:

```json
{
  "saml": {
    "enabled": true,
    "excluded-paths": ["/health", "/metrics", "/public"]
  }
}
```

### Protect Specific Paths

Specify which paths require authentication:

```json
{
  "saml": {
    "enabled": true,
    "protected-paths": ["/api", "/admin", "/dashboard"],
    "excluded-paths": ["/api/public"]
  }
}
```

## Attribute Mapping

Map SAML assertion attributes to HTTP headers sent to your backend:

```json
{
  "saml": {
    "attribute-mapping": {
      "email": "X-Auth-Email",
      "groups": "X-Auth-Groups",
      "department": "X-Auth-Department",
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": "X-Auth-DisplayName"
    }
  }
}
```

Multi-valued attributes are joined with commas:

```
SAML: groups = ["admin", "users", "developers"]
Header: X-Auth-Groups: admin,users,developers
```

## Session Cookie

The session cookie is set with security best practices:

| Flag | Default | Description |
|------|---------|-------------|
| `Secure` | `true` | Only sent over HTTPS |
| `HttpOnly` | `true` | Not accessible via JavaScript |
| `SameSite` | `Lax` | CSRF protection |
| `Path` | `/` | Cookie scope |
| `Max-Age` | `28800` | 8 hours (matches session TTL) |

Example cookie:
```
Set-Cookie: zentinel_saml_session=a1b2c3d4e5f6...; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=28800
```

## Security Considerations

### Production Checklist

- [ ] Use HTTPS for all endpoints (required by SAML spec)
- [ ] Verify IdP certificate is configured
- [ ] Set `allow-unsigned-assertions: false` (default)
- [ ] Configure appropriate `session-ttl-secs`
- [ ] Secure the session store file permissions
- [ ] Review `protected-paths` and `excluded-paths`
- [ ] Test with your IdP before going live

### Assertion Replay Prevention

The agent tracks all processed assertion IDs to prevent replay attacks. Each assertion can only be used once, even if still within its validity window.

### Clock Skew

The `clock-skew-secs` setting (default 5 minutes) allows for time differences between your server and the IdP. Increase if you see timestamp validation errors, but keep as low as practical.

## Troubleshooting

### Common Issues

**"SAML assertion not yet valid"**
- Clock skew between your server and IdP
- Increase `clock-skew-secs` or sync server time

**"SAML assertion has expired"**
- Assertion too old by the time it's processed
- Check network latency, clock sync

**"SAML assertion replay detected"**
- User refreshed the ACS page
- Browser resubmitted the POST
- Normal behavior, user should retry original URL

**"SAML response contains no assertion"**
- IdP returned an error status
- Check IdP logs for authentication failures

### Debug Logging

Enable verbose logging:

```bash
RUST_LOG=debug zentinel-auth-agent ...
```

Or via Zentinel config:
```kdl
agent "auth" {
    config {
        verbose true
    }
}
```

### Testing Without IdP

For development, you can use a test IdP like:
- [samltest.id](https://samltest.id/) - Free SAML testing service
- [Keycloak](https://www.keycloak.org/) - Run locally in Docker
- [SimpleSAMLphp](https://simplesamlphp.org/) - PHP-based test IdP
