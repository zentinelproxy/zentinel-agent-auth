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

Not in the Zentinel bundle yet: the bundle API does not list it, and the
`v0.2.0` release has no asset in the bundle's naming scheme, so
`zentinel bundle install auth` fails.

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

Zentinel 0.6.50 does not forward an `agent { config { ... } }` block to
agents, so configure the agent with the flags below. (The agent also accepts
configuration over the protocol, `on_configure`, which is the only way to
reach the modules listed under [How it works](#how-it-works).)

| Option | Default | Meaning |
|---|---|---|
| `--socket` | `/tmp/zentinel-auth.sock` | Unix socket to listen on. Env `AGENT_SOCKET`. |
| `--grpc-address` | unset | Listen on gRPC at this address (e.g. `0.0.0.0:50051`) instead of the socket. Env `GRPC_ADDRESS`. |
| `--jwt-secret` | unset | Shared secret for HMAC tokens. Takes precedence over `--jwt-public-key`. Env `JWT_SECRET`. |
| `--jwt-public-key` | unset | PEM file with an RSA or EC public key. Env `JWT_PUBLIC_KEY`. |
| `--jwt-algorithm` | `HS256` | One of `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`. Env `JWT_ALGORITHM`. |
| `--jwt-issuer` | unset | Required `iss`; not checked when unset. Env `JWT_ISSUER`. |
| `--jwt-audience` | unset | Required `aud`; not checked when unset. Env `JWT_AUDIENCE`. |
| `--api-keys` | unset | `key:name` pairs, comma-separated; `name` becomes the user ID. Env `API_KEYS`. |
| `--api-key-header` | `X-API-Key` | Header that carries the API key. Env `API_KEY_HEADER`. |
| `--basic-auth-users` | unset | `user:password` pairs, comma-separated. Passwords are compared in plain text. Env `BASIC_AUTH_USERS`. |
| `--user-id-header` | `X-User-Id` | Request header set to the authenticated user ID. Env `USER_ID_HEADER`. |
| `--auth-method-header` | `X-Auth-Method` | Request header set to the method used (`jwt`, `api_key`, `basic`, ...). Env `AUTH_METHOD_HEADER`. |
| `--fail-open` | `false` | Forward requests that fail authentication instead of answering 401. Env `FAIL_OPEN`. |
| `-v`, `--verbose` | `false` | Debug logging (JSON). Env `AUTH_VERBOSE`. |

On success the agent also sets `X-Auth-Claim-<name>` for every string-valued
JWT claim (for example `X-Auth-Claim-sub`). It does not remove headers the
client sent, so with `--fail-open` an unauthenticated request reaches the
upstream with whatever `X-User-Id` or `X-Auth-Claim-*` headers the client put
on it. Prefer passing secrets through the environment rather than the command
line.

Full reference: <https://registry.zentinelproxy.io/auth/>

## How it works

For each request the agent tries, in order: a `Bearer` token as JWT, a
`Basic` credential, then the API key header. The first that validates wins.

The code also contains these modules. Their settings are read only from
`on_configure`, which Zentinel 0.6.50 does not send, so none of them can be
turned on from a Zentinel config today. Treat them as experimental:

- OIDC: bearer tokens checked against a JWKS fetched in the background from a
  configured URL. The token's `alg` must be in `allowed-algorithms` (default:
  what the JWKS keys declare; never `none` or `HS*`), and unknown `kid`s
  refetch the JWKS at most once per `jwks-min-refetch-secs`.
- Cedar authorization (partial): policies see the principal, the HTTP method
  as the action and the path as the resource, with no entity attributes or
  context, so policies on roles or claims do not match.
- SCIM 2.0 user store (redb) that can block deactivated OIDC users.

**Refused:** a configuration that enables SAML, mTLS or token exchange is
rejected whole (`on_configure` returns false, nothing of it is applied),
because these modules do not verify what they trust
([#6](https://github.com/zentinelproxy/zentinel-agent-auth/issues/6)):

- SAML does not verify the assertion's XML signature, so a forged response
  would get a session for any user.
- mTLS reads a certificate from a request header and never verifies its chain
  against a CA, so a self-signed certificate would authenticate as any subject.
- Token exchange issues tokens with whatever scope and audience the caller
  asks for; `allowed-exchanges` and the scope mapping are not checked.

They stay refused until that verification exists.

Notes on these modules are in [`docs/`](docs/); their examples use the
proxy's `config` block, which is not forwarded.

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
