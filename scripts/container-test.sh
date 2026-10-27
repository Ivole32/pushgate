#!/usr/bin/env bash
# End-to-end container test of the real compose.yaml (Caddy + pushgate):
#   - hardening is in effect (non-root, read-only rootfs, no capabilities, no-new-privileges)
#   - requests pass through Caddy with TLS; the backend is not reachable directly
#   - a key created with the CLI works, survives `restart` and full container recreation
#   - revocation takes effect immediately
# Uses a throw-away compose project, env file and secrets; removes everything afterwards.
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash on Windows would rewrite /nodejs/... into a Windows path
cd "$(dirname "$0")/.."

PROJECT=pushgate-ctest
PORT=18443
WORK="$(mktemp -d)"
command -v cygpath >/dev/null && WORK="$(cygpath -m "$WORK")" # Windows: a path node and docker both understand
export COMPOSE_PROJECT_NAME=$PROJECT
export PUSHGATE_ENV_FILE="$WORK/env"
export SECRETS_DIR="$WORK/secrets"
export LISTEN_ADDRESS=127.0.0.1 HTTPS_PORT=$PORT PUSHGATE_HOSTNAME=localhost

cleanup() {
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*" >&2; exit 1; }

node src/cli.js gen-secrets --out "$SECRETS_DIR" >/dev/null
# Test only: the runner's uid differs from the container's, so make the throw-away secrets readable.
chmod 755 "$SECRETS_DIR"; chmod 444 "$SECRETS_DIR"/*

# Docker Desktop / rootless setups may present the client as a gateway address, so the test
# trusts private ranges. Production must list real LAN ranges only.
cat > "$PUSHGATE_ENV_FILE" <<EOF
PUBLIC_ORIGIN=https://localhost:$PORT
TRUSTED_CIDRS=127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
ADMIN_CIDRS=127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
VAPID_SUBJECT=mailto:ci@example.invalid
REQUIRE_SETUP_BEFORE_SENDING=false
EOF

up() { docker compose up -d --build --wait --wait-timeout 120 >/dev/null; }
cli() { docker compose exec -T pushgate /nodejs/bin/node src/cli.js "$@"; }
send() {
  curl -sk -o /dev/null -w '%{http_code}' --resolve "localhost:$PORT:127.0.0.1" \
    -X POST "https://localhost:$PORT/api/v1/notifications" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -d '{"title":"ctest","message":"hello"}'
}

up
pass "stack started and healthy"

CID=$(docker compose ps -q pushgate)
[ "$(docker inspect -f '{{.Config.User}}' "$CID")" = "65532:65532" ] || fail "not running as 65532"
[ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$CID")" = "true" ] || fail "rootfs not read-only"
docker inspect -f '{{.HostConfig.CapDrop}}' "$CID" | grep -q ALL || fail "capabilities not dropped"
docker inspect -f '{{.HostConfig.SecurityOpt}}' "$CID" | grep -q no-new-privileges || fail "no-new-privileges missing"
[ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$CID")" = "false" ] || fail "privileged"
[ -z "$(docker port "$CID")" ] || fail "backend port is published"
docker compose exec -T pushgate /nodejs/bin/node -e "require('fs').writeFileSync('/app/x','x')" 2>/dev/null && fail "rootfs writable"
docker compose exec -T pushgate /nodejs/bin/node -e "process.exit(process.getuid()===65532?0:1)" || fail "uid"
pass "container hardening (user, read-only rootfs, cap_drop, no-new-privileges, no published port)"

# The backend refuses direct connections (only Caddy is a trusted proxy).
DIRECT=$(docker compose exec -T pushgate /nodejs/bin/node -e "
fetch('http://127.0.0.1:8080/api/v1/notifications',{method:'POST',headers:{'X-Forwarded-For':'10.0.0.1'}})
.then(r=>console.log(r.status))")
[ "$DIRECT" = "403" ] || fail "direct backend access returned $DIRECT"
pass "direct backend access refused even with a forged X-Forwarded-For"

KEY=$(cli keys create --name ctest | head -n1)
[[ "$KEY" =~ ^pgk_ ]] || fail "key creation"
[ "$(send "$KEY")" = "200" ] || fail "valid key through Caddy"
[ "$(send "pgk_0000000000000000_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")" = "401" ] || fail "invalid key"
pass "valid key accepted, invalid key rejected (through TLS proxy)"

docker compose restart pushgate >/dev/null
docker compose up -d --wait --wait-timeout 120 >/dev/null
[ "$(send "$KEY")" = "200" ] || fail "key after restart"
pass "key works after container restart"

docker compose down >/dev/null   # removes containers, keeps named volumes
up
[ "$(send "$KEY")" = "200" ] || fail "key after recreation"
cli keys list | grep -q ctest || fail "key list after recreation"
pass "data persists across container recreation"

KEY_ID=$(echo "$KEY" | cut -d_ -f2)
cli keys revoke "$KEY_ID" >/dev/null
[ "$(send "$KEY")" = "401" ] || fail "revoked key still accepted"
pass "revocation via CLI takes effect immediately"

BACKUP_LOG=$(cli backup --out /data/ctest-backup.db)
echo "$BACKUP_LOG" | grep -q "backup written" || fail "backup"
pass "online backup"

docker compose logs pushgate 2>&1 | grep -qF -- "${KEY:21}" && fail "API key secret found in logs"
pass "API key secret not present in container logs"

echo "All container checks passed."
