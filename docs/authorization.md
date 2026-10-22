# Authorization with Cedar Policy Engine

The auth agent supports policy-based authorization using the [Cedar Policy Language](https://www.cedarpolicy.com/). Cedar enables fine-grained, attribute-based access control (ABAC).

## Overview

Authorization happens after authentication. Once a user's identity is established, Cedar policies determine whether they can perform the requested action on the requested resource.

## How It Works

```
Authenticated request
         │
         ▼
┌─────────────────────┐
│ Build Cedar Request │
│ - principal: user   │
│ - action: GET       │
│ - resource: /path   │
│ - context: claims   │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Evaluate policies   │
└─────────┬───────────┘
          │
    ┌─────┴─────┐
    │           │
    ▼           ▼
 Allow       Deny
    │           │
    ▼           ▼
 Continue    403 Forbidden
```

## Configuration

### Basic Setup

```kdl
agents {
    agent "auth" {
        config {
            authz {
                enabled true
                policy-file "/etc/zentinel/policies/auth.cedar"
                default-decision "deny"
            }
        }
    }
}
```

### Full Configuration

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

### Inline Policy

For simple configurations, embed the policy directly:

```json
{
  "authz": {
    "enabled": true,
    "policy-inline": "permit(principal, action, resource);",
    "default-decision": "deny"
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable authorization |
| `policy-file` | string | - | Path to Cedar policy file |
| `policy-inline` | string | - | Inline Cedar policy |
| `default-decision` | string | `deny` | Decision when no policy is satisfied. Never applies when a policy errors (that denies) |
| `principal-claim` | string | `sub` | Claim used as the principal ID; the authenticated user ID when the claim is absent |
| `roles-claim` | string | - | Claim containing roles: an array of strings, or one string separated by spaces or commas |
| `log-decisions` | bool | `false` | Log each decision at debug level |

The policies are compiled when the configuration arrives. A policy that does
not parse, a missing policy file or an invalid `default-decision` rejects the
whole configuration (`on_configure` returns false and nothing of it is
applied), so authorization is never left switched off or half-configured.

## Cedar Basics

Cedar policies define who can do what to which resources.

### Policy Structure

```cedar
permit(
    principal,           // Who
    action,              // What
    resource             // Which
) when {
    true                 // Conditions
};
```

### Entities

The agent creates these Cedar entities:

| Entity Type | Source | Attributes | Example |
|-------------|--------|------------|---------|
| `User` | `principal-claim`, else the user ID | `id` | `User::"john@example.com"` |
| `Action` | HTTP method (upper case) | - | `Action::"GET"` |
| `Resource` | Request path, without the query string | `path` | `Resource::"/api/users/123"` |

### Context

The context includes:

```json
{
    "roles": ["admin", "user"],        // From roles-claim; [] without it
    "claims": {                         // The verified token's claims
        "email": "john@example.com",
        "org_id": "acme"
    },
    "auth_method": "jwt",              // jwt, oidc, api_key, basic
    "path": "/api/users/123",          // Request path, no query string
    "method": "GET",                   // HTTP method
    "hour": 14                         // Current hour, UTC (0-23)
}
```

`claims` holds the claims of the verified credential with their JSON types
(strings, booleans, integers, arrays and objects). Nulls and non-integer
numbers are left out, as are object keys starting with `__`, so a claim can
never be read as a Cedar entity reference or extension value. API keys
provide `api_key_name`, Basic auth provides `username`.

Not every user has every claim. Guard optional claims with `has`
(`context.claims has org_id && context.claims.org_id == "acme"`): see
[Evaluation errors deny](#evaluation-errors-deny).

### Evaluation errors deny

Cedar skips a policy whose condition fails to evaluate, for example because
it reads a claim the user does not have. A skipped `forbid` would let the
request through, so the agent fails closed: if any policy errors, the request
is denied with `403`, whatever `default-decision` says. A request the agent
cannot express in Cedar is denied the same way.

## Example Policies

### Allow All Authenticated Users

```cedar
// Allow any authenticated user to access anything
permit(principal, action, resource);
```

### Public Endpoints

```cedar
// Allow any authenticated user to read the health check
permit(
    principal,
    action == Action::"GET",
    resource
) when {
    resource.path == "/health"
};
```

### Role-Based Access

```cedar
// Allow admins full access
permit(
    principal,
    action,
    resource
) when {
    context.roles.contains("admin")
};

// Allow users to read only
permit(
    principal,
    action == Action::"GET",
    resource
) when {
    context.roles.contains("user")
};
```

### Path-Based Access

```cedar
// Finance staff can use the reports API
permit(
    principal,
    action,
    resource
) when {
    resource.path like "/api/reports/*" &&
    context.claims has department &&
    context.claims.department == "finance"
};
```

### Method-Based Access

```cedar
// Read-only for most users
permit(
    principal,
    action == Action::"GET",
    resource
) when {
    resource.path like "/api/*"
};

// Write access for editors
permit(
    principal,
    action in [Action::"POST", Action::"PUT", Action::"DELETE"],
    resource
) when {
    context.roles.contains("editor") &&
    resource.path like "/api/*"
};
```

### Organization-Based Access

```cedar
// Allow only members of one organization
permit(
    principal,
    action,
    resource
) when {
    context.claims has org_id &&
    context.claims.org_id == "acme"
};
```

### Time-Based Access

```cedar
// Allow access only during business hours
permit(
    principal,
    action,
    resource
) when {
    context.hour >= 9 && context.hour < 17
};
```

### Deny Policies

```cedar
// Explicitly deny access to admin endpoints for non-admins
forbid(
    principal,
    action,
    resource
) when {
    resource.path like "/admin/*" &&
    !context.roles.contains("admin")
};
```

## Complete Policy Example

```cedar
// /etc/zentinel/policies/auth.cedar

// ===================
// Public Endpoints
// ===================

// Health check - any authenticated user (authorization runs only after authentication)
permit(
    principal,
    action == Action::"GET",
    resource
) when {
    resource.path == "/health" || resource.path == "/ready"
};

// ===================
// API Access
// ===================

// All authenticated users can read public API
permit(
    principal,
    action == Action::"GET",
    resource
) when {
    resource.path like "/api/public/*"
};

// Users can access their own profile (Cedar cannot build strings,
// so the path is matched against the principal's id directly)
permit(
    principal,
    action,
    resource
) when {
    context.path == "/api/me" && principal.id != ""
};

// Admins have full API access
permit(
    principal,
    action,
    resource
) when {
    context.roles.contains("admin") &&
    resource.path like "/api/*"
};

// ===================
// Admin Endpoints
// ===================

// Only admins can access admin endpoints
permit(
    principal,
    action,
    resource
) when {
    context.roles.contains("admin") &&
    resource.path like "/admin/*"
};

// ===================
// Explicit Denies
// ===================

// Never allow DELETE on critical resources
forbid(
    principal,
    action == Action::"DELETE",
    resource
) when {
    resource.path like "/api/system/*"
};
```

## Response on Denial

When authorization fails the agent answers `403 Forbidden` (body
`Forbidden`) with the audit reason code `AUTHORIZATION_DENIED`. The reason
and the deciding policies are logged at debug level.

## Debugging Policies

Enable verbose logging to see policy evaluation:

```bash
RUST_LOG=debug zentinel-auth-agent ...
```

Log output shows:
- Cedar request (principal, action, resource, context)
- Policies evaluated
- Decision and contributing policies

## Policy Best Practices

1. **Start with deny-all** - Use `default-decision: deny`
2. **Be specific** - Avoid broad `permit(principal, action, resource)`
3. **Use forbid sparingly** - Prefer explicit permits
4. **Group by function** - Organize policies logically
5. **Test policies** - Use Cedar's playground or CLI tools
6. **Version control** - Store policies in git
7. **Audit changes** - Log policy updates

## Cedar CLI Tools

Test policies locally with Cedar CLI:

```bash
# Install Cedar CLI
cargo install cedar-policy-cli

# Validate policy syntax
cedar validate --policies auth.cedar

# Test authorization
cedar authorize \
  --policies auth.cedar \
  --principal 'User::"john"' \
  --action 'Action::"GET"' \
  --resource 'Resource::"/api/users/john"' \
  --context '{"roles": ["user"]}'
```

## Security Considerations

1. **Default deny** - Always use `default-decision: deny`
2. **Guard optional claims with `has`** - a policy that errors denies the request
3. **Least privilege** - Grant minimum required access
4. **Explicit forbids** - Use for critical resources
5. **Review regularly** - Audit policies for over-permissive rules
6. **Test thoroughly** - Verify policies before deployment
7. **Secure policy files** - Restrict file permissions
