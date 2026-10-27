#!/usr/bin/env bash
# Generates the two secret files used by compose.yaml, readable only by the container user.
# Usage: scripts/gen-secrets.sh [dir]   (default: ./secrets). Requires openssl.
set -euo pipefail

DIR="${1:-secrets}"
UID_GID="65532:65532" # distroless "nonroot" user that runs pushgate

mkdir -p "$DIR"
chmod 700 "$DIR"
for f in api_key_pepper vapid_private_key; do
  if [ -e "$DIR/$f" ]; then
    echo "refusing to overwrite $DIR/$f (rotating it invalidates all API keys or device subscriptions)" >&2
    exit 1
  fi
done

umask 077
openssl rand -base64 32 > "$DIR/api_key_pepper"
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$DIR/vapid_private_key"

if [ "$(id -u)" -eq 0 ]; then
  chown "$UID_GID" "$DIR/api_key_pepper" "$DIR/vapid_private_key"
  chmod 400 "$DIR/api_key_pepper" "$DIR/vapid_private_key"
  echo "secrets written to $DIR (owner $UID_GID, mode 0400)"
else
  echo "secrets written to $DIR (mode 0600)."
  echo "On Linux, give them to the container user:  sudo chown $UID_GID $DIR/* && sudo chmod 400 $DIR/*"
fi
