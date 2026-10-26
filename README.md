<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">Auth agent</h3>

<p align="center">Checks JWT bearer tokens, API keys and Basic credentials on the request headers, and passes the authenticated identity to the upstream as headers.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-auth/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-auth/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&amp;labelColor=1f161e">
  <img alt="Rust 1.94.1+" src="https://img.shields.io/badge/rust-1.94.1%2B-f68d31?style=flat&amp;labelColor=1f161e&amp;logo=rust&amp;logoColor=white">
  <img alt="Agent protocol v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&amp;labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/auth/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

The agent answers Zentinel's `request_headers` event. A request with a valid
credential is forwarded with `X-User-Id` and `X-Auth-Method` set; a request
without one gets `401 Unauthorized` with `WWW-Authenticate: Bearer
realm="zentinel"`. Credentials are set on the command line or through
environment variables. If the agent is unreachable, the filter's
`failure-mode` decides: use `"closed"` so an outage blocks requests instead of
letting them through unauthenticated.

## Quick start

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-auth
zentinel-auth-agent --socket /tmp/zentinel-auth.sock \
  --jwt-secret "a-random-secret-of-at-least-32-characters" \
  --api-keys "sk_live_abc123:production"
```

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}

agents {
    agent "auth" type="auth" {
        unix-socket "/tmp/zentinel-auth.sock"
        events "request_headers"
        timeout-ms 100
    }
}

filters {
    filter "auth" {
        type "agent"
        agent "auth"
        failure-mode "closed"
    }
}

routes {
    route "api" {
        matches { path-prefix "/" }
        upstream "backend"
        filters "auth"
    }
}
```

```bash
curl -H "X-API-Key: sk_live_abc123" http://localhost:8080/   # forwarded, X-User-Id: production
curl http://localhost:8080/                                   # 401
```

## Install

In the Zentinel bundle from 26.10_8: `zentinel bundle install auth` installs
the `0.3.0` release the bundle lock pins, built from its tag and smoke-tested
behind a real Zentinel for `linux-x86_64`, `linux-aarch64` and
`darwin-aarch64`. Zentinel binaries up to 0.6.50 (26.10_7) keep a compiled-in
lock that does not list auth, so there the command fails.

### From source (recommended)

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-auth
```

Installs `zentinel-auth-agent`. Needs Rust 1.94.1 or newer and `protoc`; CI
also installs `pkg-config`, `libxml2-dev` and `libxmlsec1-dev`.

### Container image (build locally)

```bash
docker build -t zentinel-auth-agent .
```

## Configuration

The flags below set the agent's startup settings. Zentinel 26.10_8 and later
also send the agent block's `config { }` on every connection (releases up to
0.6.50 never did), and the agent applies it over the flags; see "Settings
from the proxy" below. That block is the only way to reach the modules listed
under [How it works](#how-it-works).

| Option | Default | Meaning |
|---|---|---|
| `--socket` | `/tmp/zentinel-auth.sock` | Unix socket to listen on. Env `AGENT_SOCKET`. |
| `--grpc-address` | unset | Listen on gRPC at this address (e.g. `0.0.0.0:50051`) instead of the socket. Env `GRPC_ADDRESS`. |
| `--jwt-secret` | unset | Shared secret for HMAC tokens. Takes precedence over `--jwt-public-key`. Env `JWT_SECRET`. |
| `--jwt-public-key` | unset | PEM file with an RSA or EC public key. Env `JWT_PUBLIC_KEY`. |
| `--jwt-algorithm` | `HS256` | One of `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`. Env `JWT_ALGORITHM`. |
| `--jwt-issuer` | unset | Required `iss`; not checked when unset. Env `JWT_ISSUER`. |
| `--jwt-audience` | unset | Required `aud`; not checked when unset. Env `JWT_AUDIENCE`. |
| `--api-keys` | unset | `key:name` pairs, comma-separated; `name` becomes the user ID. Keys are kept only as SHA-256 digests and compared in constant time. Env `API_KEYS`. |
| `--api-key-header` | `X-API-Key` | Header that carries the API key. Env `API_KEY_HEADER`. |
| `--basic-auth-users` | unset | `user:hash` pairs, comma-separated, where `hash` is a bcrypt hash (`$2a$`/`$2b$`/`$2y$`, e.g. from `htpasswd -nbB user password`). A plain-text password is refused at startup unless `--basic-auth-allow-plaintext` is set. Env `BASIC_AUTH_USERS`. |
| `--basic-auth-allow-plaintext` | `false` | Accept plain-text passwords in `--basic-auth-users` (compared in constant time; a warning is logged). Not recommended. Env `BASIC_AUTH_ALLOW_PLAINTEXT`. |
| `--user-id-header` | `X-User-Id` | Request header set to the authenticated user ID. Env `USER_ID_HEADER`. |
| `--auth-method-header` | `X-Auth-Method` | Request header set to the method used (`jwt`, `api_key`, `basic`, ...). Env `AUTH_METHOD_HEADER`. |
| `--fail-open` | `false` | Forward requests that fail authentication instead of answering 401. Env `FAIL_OPEN`. |
| `-v`, `--verbose` | `false` | Debug logging (JSON). Env `AUTH_VERBOSE`. |

On success the agent also sets `X-Auth-Claim-<name>` for every string-valued
JWT claim (for example `X-Auth-Claim-sub`).

Every request the agent lets through, on every path including
`--fail-open`, first has these headers removed: the configured user-ID and
auth-method headers, their default names `X-User-Id` and `X-Auth-Method`, the
SAML attribute headers, and every `X-Auth-Claim-*` header the client sent.
Only then are the agent's own identity headers set, so an upstream never
sees an identity the client made up. (If the agent itself is unreachable and
the filter's `failure-mode` is `"open"`, Zentinel forwards the request
without asking the agent, and nothing is removed.)

Prefer passing secrets through the environment rather than the command line.

### Settings from the proxy (`config { }`)

Zentinel 26.10_8 and later send the agent block's `config { }` on every
connection: once per pooled connection at startup and again on every
reconnect. The agent must answer each one. Keys: `jwt-secret`,
`jwt-algorithm`, `jwt-issuer`, `jwt-audience`, `api-keys`, `api-key-header`,
`basic-auth-users`, `basic-auth-allow-plaintext`, `user-id-header`,
`auth-method-header`, `fail-open`, and the `oidc`, `authz` and `scim` tables
(`saml`, `mtls` and `token-exchange` exist but are refused when enabled, see
[How it works](#how-it-works)). There is no key for `--jwt-public-key`.

- A key the block sets replaces the flag of the same name; a key it leaves
  out keeps the flag's value, with one exception: `fail-open` is taken from
  the block as is, so a block that leaves it out sets `fail-open` to `false`
  even when the agent was started with `--fail-open`.
- `api-keys` and `basic-auth-users` are lists: give several arguments. A
  single argument arrives as a string, which the agent rejects.
- A block that does not parse, fails validation (OIDC, Cedar policies, SCIM,
  Basic auth users) or enables SAML, mTLS or token exchange is rejected
  whole: `on_configure` returns false, nothing of it is applied, and the
  proxy does not use the agent (the connection fails with an ERROR log and is
  retried; meanwhile its filters' `failure-mode` applies, `closed` answering
  503).

```kdl
agent "auth" type="auth" {
    unix-socket "/tmp/zentinel-auth.sock"
    events "request_headers"
    config {
        jwt-issuer "https://issuer.example"
        api-keys "sk_live_abc123:production" "sk_test_def456:staging"
    }
}
```

Full reference: <https://registry.zentinelproxy.io/auth/>

## How it works

For each request the agent tries, in order: a `Bearer` token as JWT, a
`Basic` credential, then the API key header. The first that validates wins.

The code also contains these modules. Their settings are read only from the
agent block's `config { }` (`on_configure`), which Zentinel sends from 26.10_8
(releases up to 0.6.50 never did), so they can now be turned on from a
Zentinel config. Treat them as experimental:

- OIDC: bearer tokens checked against a JWKS fetched in the background from a
  configured URL. The token's `alg` must be in `allowed-algorithms` (default:
  what the JWKS keys declare; never `none` or `HS*`), and unknown `kid`s
  refetch the JWKS at most once per `jwks-min-refetch-secs`.
- Cedar authorization: policies see the principal (with `id`), the HTTP
  method as the action, the path as the resource (with `path`), and a context
  with the verified claims, the roles claim, the auth method, method, path
  and hour. A policy that does not parse rejects the configuration; a policy
  that errors during evaluation denies the request.
- SCIM 2.0 user store (redb) that can block deactivated OIDC users. Its
  endpoint takes the static bearer token (compared in constant time) or an
  OIDC token carrying `required-scope` (default `scim`; cannot be empty).

**Refused:** a configuration that enables SAML, mTLS or token exchange is
rejected whole (`on_configure` returns false, nothing of it is applied, and
Zentinel 26.10_8 then does not use the agent: its routes follow their
`failure-mode`), because these modules do not verify what they trust
([#6](https://github.com/zentinelproxy/zentinel-agent-auth/issues/6)):

- SAML does not verify the assertion's XML signature, so a forged response
  would get a session for any user.
- mTLS reads a certificate from a request header and never verifies its chain
  against a CA, so a self-signed certificate would authenticate as any subject.
- Token exchange issues tokens with whatever scope and audience the caller
  asks for; `allowed-exchanges` and the scope mapping are not checked.

They stay refused until that verification exists.

Notes on these modules are in [`docs/`](docs/); their examples use the
proxy's `config { }` block, which Zentinel sends from 26.10_8.

## Development

```bash
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Minimum toolchain: Rust 1.94.1 (`rust-version` in `Cargo.toml`), plus
`protoc`.

## Related

- [Registry page](https://registry.zentinelproxy.io/auth/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
