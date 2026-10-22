#!/usr/bin/env bash
# Smoke test: run the agent binary behind a real Zentinel (fail-closed) with
# the shared harness from zentinelproxy/.github (agent-smoke/smoke.py).
#
#   AGENT_SMOKE=<path to smoke.py> scripts/smoke-test.sh [<agent-binary> <zentinel-binary>]
#
# The binaries default to $AGENT_BIN and $ZENTINEL_BIN, which the shared
# release workflow sets. Run by that workflow on every platform before any
# asset is published, and by CI on every push and pull request.
#
# Checks, over the Unix socket and over gRPC:
#   * the v2 handshake works and a request with a valid API key is forwarded
#     to the upstream (200) with X-User-Id set by the agent, also when the
#     client sent its own X-User-Id;
#   * a request without an API key, and one with a wrong key, get 401 and
#     never reach the upstream;
#   * with the agent stopped the valid request is refused (agent on the path).

set -euo pipefail

AGENT_BIN=${1:-${AGENT_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
ZENTINEL_BIN=${2:-${ZENTINEL_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
AGENT_SMOKE=${AGENT_SMOKE:?set AGENT_SMOKE to agent-smoke/smoke.py from zentinelproxy/.github}

KEY="smoke-key-$$-$RANDOM"
cases=(
    --clean "{\"name\": \"valid API key\", \"path\": \"/smoke\", \"headers\": {\"X-API-Key\": \"$KEY\"}, \"upstream_headers\": {\"X-User-Id\": \"smoke\", \"X-Auth-Method\": null}}"
    --case "{\"name\": \"valid key with a forged X-User-Id\", \"path\": \"/smoke\", \"headers\": {\"X-API-Key\": \"$KEY\", \"X-User-Id\": \"admin\"}, \"expect\": 200, \"upstream_headers\": {\"X-User-Id\": \"smoke\"}}"
    --case '{"name": "missing API key", "path": "/smoke", "expect": 401}'
    --case '{"name": "wrong API key", "path": "/smoke", "headers": {"X-API-Key": "not-the-key"}, "expect": 401}'
)

for transport in uds grpc; do
    echo "=== auth agent over $transport"
    python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" \
        --name auth --type auth --transport "$transport" \
        --agent-arg=--api-keys --agent-arg "$KEY:smoke" \
        "${cases[@]}"
done
