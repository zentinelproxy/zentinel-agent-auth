# SCIM 2.0 Provisioning

This guide covers SCIM 2.0 (RFC 7644) user provisioning for the Zentinel Auth Agent. SCIM allows Identity Providers (IdPs) like Kanidm, Keycloak, Okta, and Azure AD to automatically push user create, update, and delete events.

## Overview

Without SCIM, API keys and basic auth users are static — configured at startup or via `on_configure`. SCIM adds dynamic provisioning: your IdP manages user lifecycle and pushes changes to the agent in real time.

### Supported Features

- **User CRUD** — Create, read, update (PUT and PATCH), and delete users
- **Filtering** — `externalId eq "..."` and `userName eq "..."` queries
- **Pagination** — `startIndex` and `count` parameters for list operations
- **PATCH operations** — `replace`, `add`, `remove` with dot-path notation (`name.givenName`)
- **Persistent storage** — Users stored in embedded database (redb) with in-memory cache
- **Secondary indexes** — O(1) lookup by `externalId` and `userName`
- **OIDC integration** — Deactivated SCIM users are blocked during OIDC authentication
- **Dual auth** — SCIM endpoint secured by static bearer token or OIDC token validation

### How It Works

```
┌────────────┐     ┌──────────────────┐     ┌──────────┐
│    IdP     │     │   Auth Agent     │     │  redb    │
│ (Keycloak, │     │                  │     │ Database │
│  Kanidm,   │     │  ┌────────────┐  │     └────┬─────┘
│  Okta)     │     │  │ SCIM API   │  │          │
└─────┬──────┘     │  └────────────┘  │          │
      │            │  ┌────────────┐  │          │
      │            │  │ User Store │──┼──────────┤
      │            │  └────────────┘  │          │
      │            └────────┬─────────┘          │
      │                     │                    │
      │  POST /scim/v2/Users│                    │
      ├────────────────────▶│ create user        │
      │                     ├───────────────────▶│
      │   201 Created       │                    │
      │◀────────────────────┤                    │
      │                     │                    │
      │  PATCH /scim/v2/Users/{id}               │
      ├────────────────────▶│ update user        │
      │                     ├───────────────────▶│
      │   200 OK            │                    │
      │◀────────────────────┤                    │
      │                     │                    │
      │  DELETE /scim/v2/Users/{id}              │
      ├────────────────────▶│ deactivate user    │
      │                     ├───────────────────▶│
      │   204 No Content    │                    │
      │◀────────────────────┤                    │
      └                     └                    └
```

When `enforce-active-status` is enabled, deactivated SCIM users are automatically blocked during OIDC authentication:

```
┌────────┐     ┌─────────┐     ┌──────────┐     ┌────────────┐
│ Client │     │ Zentinel│     │Auth Agent│     │ SCIM Store │
└───┬────┘     └────┬────┘     └────┬─────┘     └─────┬──────┘
    │               │               │                  │
    │ Bearer token  │               │                  │
    ├──────────────▶│               │                  │
    │               │ Check auth    │                  │
    │               ├──────────────▶│                  │
    │               │               │ OIDC validates ✓ │
    │               │               │ Check SCIM user  │
    │               │               ├─────────────────▶│
    │               │               │ active: false    │
    │               │               │◀─────────────────┤
    │               │  403 Account  │                  │
    │               │  deactivated  │                  │
    │  403          │◀──────────────┤                  │
    │◀──────────────┤               │                  │
    └               └               └                  └
```

## Configuration

### Minimal Configuration (Static Bearer Token)

```json
{
  "scim": {
    "enabled": true,
    "bearer-token": "your-scim-provisioning-secret"
  }
}
```

### Minimal Configuration (OIDC Auth)

```json
{
  "scim": {
    "enabled": true,
    "use-oidc-auth": true
  }
}
```

This reuses the existing OIDC validator — no additional configuration needed if OIDC is already set up.

### Complete Configuration

```json
{
  "scim": {
    "enabled": true,
    "base-path": "/scim/v2",
    "bearer-token": "your-scim-provisioning-secret",
    "use-oidc-auth": true,
    "required-scope": "scim:write",
    "store-path": "/var/lib/zentinel-auth/scim_users.redb",
    "enforce-active-status": true,
    "location-base-url": "https://auth.example.com/scim/v2"
  }
}
```

### Zentinel Proxy Configuration

```kdl
agents {
    agent "auth" type="auth" {
        grpc "http://auth-service:50051"
        events "request_headers" "request_body_chunk"
        timeout-ms 100
        failure-mode "closed"

        config {
            // ... other auth config ...

            scim {
                enabled true
                bearer-token "your-scim-provisioning-secret"
                enforce-active-status true
            }
        }
    }
}
```

**Important:** SCIM requires `request_body_chunk` in the events list because POST, PUT, and PATCH operations send a JSON body.

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable SCIM provisioning endpoint |
| `base-path` | string | `/scim/v2` | Base path for SCIM endpoints |
| `bearer-token` | string | - | Static bearer token for SCIM auth |
| `use-oidc-auth` | bool | `true` | Use OIDC token validation for SCIM auth |
| `required-scope` | string | - | Required OAuth scope (e.g. `scim:write`) |
| `store-path` | string | `/var/lib/zentinel-auth/scim_users.redb` | Path to SCIM user database file |
| `enforce-active-status` | bool | `true` | Block deactivated SCIM users during OIDC auth |
| `location-base-url` | string | - | Base URL for `meta.location` (defaults to `base-path`) |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SCIM_STORE_PATH` | Path to SCIM user database | `/var/lib/zentinel-auth/scim_users.redb` |
| `SCIM_BEARER_TOKEN` | Static bearer token (alternative to config) | - |

## SCIM Endpoints

All endpoints require authentication via bearer token (static or OIDC).

### Create User

```bash
curl -X POST https://proxy.example.com/scim/v2/Users \
  -H "Authorization: Bearer your-scim-provisioning-secret" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "jdoe",
    "externalId": "oidc-subject-id",
    "name": {
      "givenName": "John",
      "familyName": "Doe"
    },
    "displayName": "John Doe",
    "emails": [{"value": "jdoe@example.com", "type": "work", "primary": true}],
    "active": true
  }'
```

Response (201 Created):

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "userName": "jdoe",
  "externalId": "oidc-subject-id",
  "name": {"givenName": "John", "familyName": "Doe"},
  "displayName": "John Doe",
  "emails": [{"value": "jdoe@example.com", "type": "work", "primary": true}],
  "active": true,
  "meta": {
    "resourceType": "User",
    "created": "2026-02-19T10:30:00Z",
    "lastModified": "2026-02-19T10:30:00Z",
    "location": "https://auth.example.com/scim/v2/Users/f47ac10b-58cc-4372-a567-0e02b2c3d479"
  }
}
```

### Get User

```bash
curl https://proxy.example.com/scim/v2/Users/f47ac10b-58cc-4372-a567-0e02b2c3d479 \
  -H "Authorization: Bearer your-scim-provisioning-secret"
```

### List Users

```bash
# List all users (paginated)
curl "https://proxy.example.com/scim/v2/Users?startIndex=1&count=25" \
  -H "Authorization: Bearer your-scim-provisioning-secret"

# Filter by externalId (what IdPs use for sync)
curl "https://proxy.example.com/scim/v2/Users?filter=externalId+eq+%22oidc-subject-id%22" \
  -H "Authorization: Bearer your-scim-provisioning-secret"

# Filter by userName
curl "https://proxy.example.com/scim/v2/Users?filter=userName+eq+%22jdoe%22" \
  -H "Authorization: Bearer your-scim-provisioning-secret"
```

### Replace User (PUT)

```bash
curl -X PUT https://proxy.example.com/scim/v2/Users/f47ac10b-58cc-4372-a567-0e02b2c3d479 \
  -H "Authorization: Bearer your-scim-provisioning-secret" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "john.doe",
    "displayName": "John A. Doe",
    "active": true
  }'
```

### Patch User

```bash
# Deactivate a user
curl -X PATCH https://proxy.example.com/scim/v2/Users/f47ac10b-58cc-4372-a567-0e02b2c3d479 \
  -H "Authorization: Bearer your-scim-provisioning-secret" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {"op": "replace", "path": "active", "value": false}
    ]
  }'

# Update name fields
curl -X PATCH https://proxy.example.com/scim/v2/Users/f47ac10b-58cc-4372-a567-0e02b2c3d479 \
  -H "Authorization: Bearer your-scim-provisioning-secret" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {"op": "replace", "path": "name.givenName", "value": "Jane"},
      {"op": "add", "path": "displayName", "value": "Jane Doe"}
    ]
  }'
```

#### Supported PATCH Paths

| Path | Type | Operations | Description |
|------|------|------------|-------------|
| `userName` | string | replace, add | Unique username |
| `displayName` | string | replace, add, remove | Display name |
| `active` | bool | replace, add | Active status |
| `externalId` | string | replace, add, remove | External identifier |
| `name.givenName` | string | replace, add, remove | First name |
| `name.familyName` | string | replace, add, remove | Last name |
| `name.formatted` | string | replace, add, remove | Full formatted name |
| `name` | object | remove | Clear entire name |
| `emails` | array | replace, add, remove | Email addresses |

### Delete User

```bash
curl -X DELETE https://proxy.example.com/scim/v2/Users/f47ac10b-58cc-4372-a567-0e02b2c3d479 \
  -H "Authorization: Bearer your-scim-provisioning-secret"
```

Returns 204 No Content. The user is deactivated (set `active: false`) rather than permanently deleted, per SCIM convention.

## Response Codes

| Code | Description |
|------|-------------|
| 200 | Success (GET, PUT, PATCH) |
| 201 | User created (POST) — includes `Location` header |
| 204 | User deleted (DELETE) |
| 400 | Invalid request body, unsupported filter, or bad patch operation |
| 401 | Missing or invalid bearer token |
| 404 | User not found |
| 409 | `userName` conflict (uniqueness violation) |
| 503 | SCIM store not initialized |

All error responses use `application/scim+json` content type with the standard SCIM error format:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "detail": "userName 'jdoe' already exists",
  "status": "409",
  "scimType": "uniqueness"
}
```

## IdP Setup Guides

### Keycloak

1. Go to **Realm Settings → User Federation → Add provider → SCIM**
2. Set the SCIM endpoint URL: `https://proxy.example.com/scim/v2`
3. Set the bearer token in the authentication section
4. Configure attribute mapping (Keycloak maps `sub` to `externalId` by default)
5. Enable synchronization

### Kanidm

1. Configure a SCIM sync endpoint in your Kanidm configuration
2. Set the endpoint URL and bearer token
3. Kanidm will push user create/update/delete events automatically

### Azure AD (Entra ID)

1. Go to **Enterprise Applications → Your App → Provisioning**
2. Set provisioning mode to **Automatic**
3. Set tenant URL to `https://proxy.example.com/scim/v2`
4. Set secret token to your bearer token
5. Test connection, then save and start provisioning
6. Azure AD maps `objectId` to `externalId` by default

### Okta

1. Go to **Applications → Your App → Provisioning → Integration**
2. Check **Enable API Integration**
3. Set SCIM connector base URL to `https://proxy.example.com/scim/v2`
4. Set API token to your bearer token
5. Under **To App**, enable Create Users, Update User Attributes, and Deactivate Users

## Filtering

Only two filter expressions are supported (sufficient for IdP sync operations):

```
externalId eq "value"
userName eq "value"
```

Any other filter expression returns a 400 error. This covers the filters that IdPs like Okta, Azure AD, and Keycloak use when checking if a user already exists before provisioning.

## Storage

SCIM users are stored in a separate redb database file (default: `/var/lib/zentinel-auth/scim_users.redb`).

### Tables

| Table | Key | Value | Purpose |
|-------|-----|-------|---------|
| `scim_users` | UUID | MessagePack(ScimUser) | Primary user storage |
| `scim_ext_index` | externalId | UUID | O(1) lookup by IdP identifier |
| `scim_username_index` | userName | UUID | O(1) lookup by username |

All three tables are updated atomically within a single write transaction when creating, replacing, or deleting users.

An in-memory cache mirrors all three tables for fast reads. The cache is populated from the database on startup.

## Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `scim_requests_total` | counter | Total SCIM API requests processed |

## Security Considerations

1. **Use strong bearer tokens** — Generate a random token of at least 32 characters. Treat it like a password.
2. **Prefer OIDC auth in production** — Set `use-oidc-auth: true` and `required-scope: "scim:write"` so only authorized service accounts can provision users.
3. **Restrict network access** — SCIM endpoints should only be accessible from your IdP. Use firewall rules or Zentinel route matching to limit access.
4. **Enable `enforce-active-status`** — This blocks deactivated users during OIDC auth, ensuring that deprovisioning in your IdP immediately revokes access.
5. **Separate database file** — The SCIM store uses a separate file from the SAML session store. Back it up as part of your data management strategy.
6. **Password field** — The SCIM API accepts a `password` field in create/update requests (some IdPs send it) but never stores or returns it.
