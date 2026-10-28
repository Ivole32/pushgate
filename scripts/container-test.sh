#!/usr/bin/env bash
# End-to-end container test of the real compose.yaml:
#   - the image works when built from an owner-only (umask 077) checkout
#   - hardening is in effect (non-root, read-only rootfs, no capabilities, no-new-privileges)
#   - the port is published on 127.0.0.1 only, inside 2000-2999
#   - the host reverse proxy (simulated with curl on 127.0.0.1) is the only trusted forwarder;
#     the forwarded client must still be inside TRUSTED_CIDRS
#   - a key created with the CLI works, survives `restart` and full container recreation
#   - revocation takes effect immediately
# Uses a throw-away compose project, env file and secrets; removes everything afterwards.
#
# The default network is the production one (172.20.2.0/24). On a machine where that range is
# already taken, override it for the test only, e.g.:
#   PUSHGATE_SUBNET=172.29.2.0/24 PUSHGATE_GATEWAY=172.29.2.1 PUSHGATE_IP=172.29.2.10 npm run test:container
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash on Windows would rewrite /nodejs/... into a Windows path
cd "$(dirname "$0")/.."

export COMPOSE_PROJECT_NAME=pushgate-ctest
export PUSHGATE_PORT="${PUSHGATE_PORT:-2581}"
WORK="$(mktemp -d)"
command -v cygpath >/dev/null && WORK="$(cygpath -m "$WORK")" # Windows: a path node and docker both understand
export PUSHGATE_ENV_FILE="$WORK/env"
export SECRETS_DIR="$WORK/secrets"
BASE="http://127.0.0.1:$PUSHGATE_PORT"
LAN_CLIENT=192.168.50.20   # stands in for a LAN client, as the host proxy would report it

cleanup() {
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*" >&2; exit 1; }

node src/cli.js gen-secrets --out "$SECRETS_DIR" >/dev/null
# Same permission layout as production (scripts/gen-secrets.sh): private directory, 0444 files.
bash scripts/gen-secrets.sh --fix-permissions "$SECRETS_DIR" >/dev/null

cat > "$PUSHGATE_ENV_FILE" <<EOF
PUBLIC_ORIGIN=https://notify.ctest.example
TRUSTED_CIDRS=192.168.50.0/24
ADMIN_CIDRS=192.168.50.0/24
VAPID_SUBJECT=mailto:ci@example.invalid
REQUIRE_SETUP_BEFORE_SENDING=false
EOF

up() { docker compose up -d --build --wait --wait-timeout 120 >/dev/null; }
cli() { docker compose exec -T pushgate /nodejs/bin/node src/cli.js "$@"; }
# send <key> [x-forwarded-for]
send() {
  curl -s -o "$WORK/response" -w '%{http_code}' -X POST "$BASE/api/v1/notifications" \
    -H "X-Forwarded-For: ${2:-$LAN_CLIENT}" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -d '{"title":"ctest","message":"hello"}'
}

# A checkout made with a strict umask (077) has owner-only files. The image must still be
# readable by the non-root runtime user (and not writable by it).
tar --mode="go-rwx" -cf - Dockerfile .dockerignore package.json package-lock.json src public > "$WORK/strict.tar"
docker build -q -t pushgate:ctest-strict - < "$WORK/strict.tar" >/dev/null
docker run --rm pushgate:ctest-strict src/cli.js --help >/dev/null 2>&1 \
  || { docker rmi -f pushgate:ctest-strict >/dev/null; fail "image built from an owner-only checkout cannot start"; }
docker run --rm --entrypoint /nodejs/bin/node pushgate:ctest-strict -e "require('fs').writeFileSync('/app/src/x','x')" 2>/dev/null \
  && { docker rmi -f pushgate:ctest-strict >/dev/null; fail "application files writable by the runtime user"; }
docker rmi -f pushgate:ctest-strict >/dev/null
pass "image built from a umask-077 checkout runs; app files not writable by the runtime user"

up
pass "stack started and healthy"

CID=$(docker compose ps -q pushgate)
[ "$(docker inspect -f '{{.Config.User}}' "$CID")" = "65532:65532" ] || fail "not running as 65532"
[ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$CID")" = "true" ] || fail "rootfs not read-only"
docker inspect -f '{{.HostConfig.CapDrop}}' "$CID" | grep -q ALL || fail "capabilities not dropped"
docker inspect -f '{{.HostConfig.SecurityOpt}}' "$CID" | grep -q no-new-privileges || fail "no-new-privileges missing"
[ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$CID")" = "false" ] || fail "privileged"
docker compose exec -T pushgate /nodejs/bin/node -e "require('fs').writeFileSync('/app/x','x')" 2>/dev/null && fail "rootfs writable"
docker compose exec -T pushgate /nodejs/bin/node -e "process.exit(process.getuid()===65532?0:1)" || fail "uid"
pass "container hardening (user, read-only rootfs, cap_drop, no-new-privileges)"

BINDINGS=$(docker inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{range $b}}{{.HostIp}}:{{.HostPort}} {{end}}{{end}}' "$CID")
for b in $BINDINGS; do
  host=${b%:*}; port=${b##*:}
  [ "$host" = "127.0.0.1" ] || fail "port published on $host"
  [ "$port" -ge 2000 ] && [ "$port" -le 2999 ] || fail "port $port outside 2000-2999"
done
[ -n "$BINDINGS" ] || fail "no published port"
pass "published only on loopback, inside 2000-2999 ($BINDINGS)"

KEY=$(cli keys create --name ctest | head -n1)
[[ "$KEY" =~ ^pgk_ ]] || fail "key creation"

# The loopback-published port must reach the container from the network gateway (the trusted
# proxy). If this fails, the Docker setup rewrites sources differently: check TRUSTED_PROXIES.
CODE=$(send "$KEY")
if [ "$CODE" != "200" ]; then
  docker compose logs pushgate 2>&1 | grep '"msg":"request"' | tail -n 3 >&2
  fail "valid key via host proxy returned $CODE (expected 200; see the client ip above)"
fi
pass "host proxy -> loopback port -> pushgate accepted (gateway is the trusted proxy)"

[ "$(send "pgk_0000000000000000_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")" = "401" ] || fail "invalid key"
[ "$(send "$KEY" 10.9.9.9)" = "403" ] || fail "forwarded client outside TRUSTED_CIDRS accepted"
[ "$(send "$KEY" "10.9.9.9, $LAN_CLIENT")" = "403" ] || fail "appended forwarding header accepted"
NOXFF=$(curl -s -o "$WORK/response" -w '%{http_code}' -X POST "$BASE/api/v1/notifications" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d '{"title":"a","message":"b"}')
[ "$NOXFF" = "403" ] || fail "request without forwarding header accepted ($NOXFF)"
pass "invalid key 401; untrusted, appended or missing X-Forwarded-For 403"

# Other clients on the Docker network (here: the container itself) are not trusted proxies.
DIRECT=$(docker compose exec -T pushgate /nodejs/bin/node -e "
fetch('http://127.0.0.1:8080/api/v1/notifications',{method:'POST',headers:{'X-Forwarded-For':'$LAN_CLIENT'}})
.then(r=>console.log(r.status))")
[ "$DIRECT" = "403" ] || fail "direct backend access returned $DIRECT"
pass "direct backend access refused even with a forged X-Forwarded-For"

docker compose restart pushgate >/dev/null
docker compose up -d --wait --wait-timeout 120 >/dev/null
[ "$(send "$KEY")" = "200" ] || fail "key after restart"
pass "key works after container restart"

docker compose down >/dev/null   # removes containers and network, keeps named volumes
up
[ "$(send "$KEY")" = "200" ] || fail "key after recreation"
cli keys list | grep -q ctest || fail "key list after recreation"
pass "data persists across container recreation"

KEY_ID=$(echo "$KEY" | cut -d_ -f2)
cli keys revoke "$KEY_ID" >/dev/null
[ "$(send "$KEY")" = "401" ] || fail "revoked key still accepted"
pass "revocation via CLI takes effect immediately"

cli backup --out /data/ctest-backup.db | grep -q "backup written" || fail "backup"
pass "online backup"

docker compose logs pushgate 2>&1 | grep -qF -- "${KEY:21}" && fail "API key secret found in logs"
pass "API key secret not present in container logs"

echo "All container checks passed."
