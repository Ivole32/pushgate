#!/usr/bin/env bash
# Generates the two secret files used by compose.yaml.
#
# Usage: scripts/gen-secrets.sh [dir]                     create secrets (default dir: ./secrets)
#        scripts/gen-secrets.sh --fix-permissions [dir]   only (re)apply the permission layout
#
# Permission layout (works with plain Docker, user-namespace remapping and rootless Docker):
#   directory  0700  -> other host users cannot reach the files
#   files      0444  -> readable by the container user, whatever host uid it is mapped to
# Compose bind-mounts each file directly to /run/secrets/<name>, so the container never needs
# access to the directory itself. Do not loosen the directory permissions.
set -euo pipefail

FIX=0
if [ "${1:-}" = "--fix-permissions" ]; then FIX=1; shift; fi
DIR="${1:-secrets}"
FILES=(api_key_pepper vapid_private_key)

apply_permissions() {
  chmod 700 "$DIR"
  chmod 444 "${FILES[@]/#/$DIR/}"
  echo "permissions: $DIR 0700, files 0444"
}

if [ "$FIX" -eq 1 ]; then
  for f in "${FILES[@]}"; do [ -f "$DIR/$f" ] || { echo "missing $DIR/$f" >&2; exit 1; }; done
  apply_permissions
  exit 0
fi

mkdir -p "$DIR"
chmod 700 "$DIR"
for f in "${FILES[@]}"; do
  if [ -e "$DIR/$f" ]; then
    echo "refusing to overwrite $DIR/$f (rotating it invalidates all API keys or device subscriptions)" >&2
    echo "to repair permissions only: $0 --fix-permissions $DIR" >&2
    exit 1
  fi
done

umask 077
openssl rand -base64 32 > "$DIR/api_key_pepper"
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$DIR/vapid_private_key"
apply_permissions
echo "secrets written to $DIR"
