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
                policy-file "/etc/sentinel/policies/auth.cedar"
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
    "policy-file": "/etc/sentinel/policies/auth.cedar",
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
| `default-decision` | string | `deny` | Default when no policy matches |
| `principal-claim` | string | `sub` | JWT claim for principal ID |
| `roles-claim` | string | - | JWT claim containing roles |

## Cedar Basics

Cedar policies define who can do what to which resources.

### Policy Structure

```cedar
permit(
    principal,           // Who
    action,              // What
    resource             // Which
) when {
    // Conditions
};
```

### Entities

The agent creates these Cedar entities:

| Entity Type | Source | Example |
|-------------|--------|---------|
| `User` | Authenticated user ID | `User::"john@example.com"` |
| `Action` | HTTP method | `Action::"GET"` |
| `Resource` | Request path | `Resource::"/api/users/123"` |

### Context

The context includes:

```cedar
{
    "roles": ["admin", "user"],        // From roles claim
    "claims": {                         // All JWT claims
        "email": "john@example.com",
        "org_id": "acme"
    },
    "auth_method": "jwt",              // How user authenticated
    "path": "/api/users/123",          // Request path
    "method": "GET"                    // HTTP method
}
```

## Example Policies

### Allow All Authenticated Users

```cedar
// Allow any authenticated user to access anything
permit(principal, action, resource);
```

### Public Endpoints

```cedar
// Allow unauthenticated access to health check
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
// Allow access to user's own resources
permit(
    principal,
    action,
    resource
) when {
    resource.path like "/api/users/*" &&
    resource.path.endsWith(principal.id)
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
// Allow access only to own organization's resources
permit(
    principal,
    action,
    resource
) when {
    context.claims.org_id == resource.org_id
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
// /etc/sentinel/policies/auth.cedar

// ===================
// Public Endpoints
// ===================

// Health check - no auth required
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

// Users can access their own data
permit(
    principal,
    action,
    resource
) when {
    resource.path like "/api/users/*" &&
    context.claims.sub == resource.path.split("/").last()
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

## Headers on Denial

When authorization fails:

| Header | Description | Example |
|--------|-------------|---------|
| `X-Authz-Decision` | Decision result | `deny` |
| `X-Authz-Reason` | Why denied | `No matching permit policy` |

Response: `403 Forbidden`

## Debugging Policies

Enable verbose logging to see policy evaluation:

```bash
RUST_LOG=debug sentinel-auth-agent ...
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
2. **Least privilege** - Grant minimum required access
3. **Explicit forbids** - Use for critical resources
4. **Review regularly** - Audit policies for over-permissive rules
5. **Test thoroughly** - Verify policies before deployment
6. **Secure policy files** - Restrict file permissions
