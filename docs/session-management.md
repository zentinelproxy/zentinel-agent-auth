# Session Management

The auth agent includes a built-in session persistence layer for SAML authentication. Sessions are stored in an embedded database (redb) and survive agent restarts.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Auth Agent                     │
│  ┌───────────────────────────────────────────┐  │
│  │            Session Store                  │  │
│  │  ┌─────────────────┐  ┌────────────────┐  │  │
│  │  │  In-Memory      │  │    redb        │  │  │
│  │  │  Cache          │◀─┤    Database    │  │  │
│  │  │  (hot sessions) │  │  (persistent)  │  │  │
│  │  └─────────────────┘  └────────────────┘  │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │         Background Cleanup Task           │  │
│  │    (evicts expired sessions periodically) │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

## Storage

### Database

Sessions are persisted using [redb](https://github.com/cberner/redb), a lightweight embedded key-value store written in Rust. Features:

- ACID transactions
- Zero external dependencies
- Crash-safe
- Single-file database

### Tables

| Table | Key | Value | Purpose |
|-------|-----|-------|---------|
| `saml_sessions` | Session ID (hex) | Session data (MessagePack) | Store active sessions |
| `saml_assertions` | Assertion ID | Expiry timestamp | Replay prevention |

### File Location

Default path: `/var/lib/zentinel-auth/sessions.redb`

Configure via:
```json
{
  "saml": {
    "session-store-path": "/path/to/sessions.redb"
  }
}
```

The agent creates the parent directory if it doesn't exist.

### File Permissions

The database file should be readable/writable only by the agent process:

```bash
chmod 600 /var/lib/zentinel-auth/sessions.redb
chown zentinel:zentinel /var/lib/zentinel-auth/sessions.redb
```

## Session Lifecycle

### Creation

1. User completes SAML authentication
2. Agent validates assertion
3. Session created with:
   - Unique session ID (128-bit random)
   - User ID from NameID
   - Attributes from assertion
   - Expiry based on `session-ttl-secs`
4. Assertion ID recorded (replay prevention)
5. Session stored in database and cache
6. Cookie set in response

### Validation

1. Request arrives with session cookie
2. Agent parses session ID from cookie
3. Lookup in cache (fast path)
4. If not in cache, lookup in database
5. Check expiry
6. If valid: update last-accessed time, return user info
7. If expired/missing: trigger SAML redirect

### Expiry

Sessions expire based on `session-ttl-secs` (default 8 hours). Expiry is checked:

- On every session lookup
- During background cleanup

### Deletion

Sessions are deleted when:

- They expire (via cleanup task)
- User initiates logout (if SLO configured)
- Manually via admin action

## In-Memory Cache

For performance, recently accessed sessions are cached in memory:

| Setting | Value |
|---------|-------|
| Max cached sessions | 10,000 |
| Cache eviction | LRU (least recently used) |
| Cache invalidation | On session delete/expire |

Cache behavior:

- Cache hit: ~microseconds
- Cache miss + DB lookup: ~milliseconds
- Session updates write-through to DB

## Background Cleanup

A background task periodically removes expired sessions:

```
┌─────────────────────────────────────────┐
│           Cleanup Task                  │
│  ┌─────────────────────────────────┐    │
│  │  Every cleanup-interval-secs:   │    │
│  │  1. Scan sessions table         │    │
│  │  2. Delete expired sessions     │    │
│  │  3. Scan assertions table       │    │
│  │  4. Delete expired assertions   │    │
│  │  5. Log eviction count          │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

Configuration:

```json
{
  "saml": {
    "cleanup-interval-secs": 300
  }
}
```

Default: 5 minutes (300 seconds)

## Session Data

Each session stores:

| Field | Type | Description |
|-------|------|-------------|
| `id` | SessionId | 128-bit random identifier |
| `user_id` | String | NameID from SAML assertion |
| `created_at` | DateTime | Session creation time |
| `expires_at` | DateTime | Session expiry time |
| `last_accessed` | DateTime | Last request time |
| `assertion_id` | String | Original SAML assertion ID |
| `idp_entity_id` | String | IdP that issued the assertion |
| `name_id_format` | Option | NameID format (if specified) |
| `session_index` | Option | SAML SessionIndex (for SLO) |
| `attributes` | HashMap | SAML attributes |
| `client_ip` | Option | Client IP at session creation |

## Replay Prevention

To prevent assertion replay attacks, the agent tracks all processed assertion IDs:

1. When processing a SAML response, check if assertion ID exists
2. If exists → reject with "replay detected" error
3. If new → store assertion ID with expiry timestamp
4. Background cleanup removes expired assertion records

This ensures each SAML assertion can only be used once, even if the user resubmits the form.

## Scaling Considerations

### Single Instance

The embedded database is designed for single-instance deployments. Each agent instance maintains its own session store.

### Multiple Instances

For multiple agent instances behind a load balancer:

**Option 1: Sticky Sessions**
- Configure load balancer for session affinity
- Each user always hits the same agent instance

**Option 2: Shared Storage**
- Mount a shared filesystem (NFS, EFS)
- All instances use the same database file
- Note: redb supports multiple readers, single writer

**Option 3: External Session Store** (future)
- Redis/Valkey backend
- Database backend (PostgreSQL)
- Not yet implemented

### High Availability

For HA deployments:

1. Use sticky sessions at the load balancer
2. Accept that session is lost if agent crashes (user re-authenticates)
3. Keep session TTL reasonable (8 hours default)

## Monitoring

### Metrics

The agent logs session metrics:

```
Loaded active sessions into cache (sessions=42)
Session created for user@example.com
Session cleanup: evicted 15 expired sessions
```

### Database Size

Monitor database file size:

```bash
ls -lh /var/lib/zentinel-auth/sessions.redb
```

Typical size: ~1KB per active session

### Health Check

The agent remains healthy as long as:
- Database file is accessible
- Background cleanup task is running
- No transaction deadlocks

## Backup and Recovery

### Backup

To backup sessions:

```bash
# Stop agent or ensure no writes
cp /var/lib/zentinel-auth/sessions.redb /backup/sessions.redb.bak
```

### Recovery

To restore:

```bash
# Stop agent
cp /backup/sessions.redb.bak /var/lib/zentinel-auth/sessions.redb
# Start agent
```

### Clean Start

To clear all sessions:

```bash
# Stop agent
rm /var/lib/zentinel-auth/sessions.redb
# Start agent (creates fresh database)
```

## Troubleshooting

### "Session store not initialized"

- SAML is enabled but session store failed to open
- Check file permissions
- Check disk space
- Check parent directory exists

### "Session not found or expired"

- Normal if session expired
- User should re-authenticate
- Check `session-ttl-secs` is appropriate

### "Failed to open session database"

- File permissions issue
- Disk full
- Corrupted database file

### Database Corruption

If the database becomes corrupted:

```bash
# Stop agent
rm /var/lib/zentinel-auth/sessions.redb
# Start agent (users will need to re-authenticate)
```

### Disk Space

If disk fills up:

1. Stop agent
2. Free disk space
3. Optionally delete old database
4. Start agent

The agent handles cleanup automatically, but requires disk space for transactions.
