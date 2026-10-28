#!/usr/bin/env bash
# Dependency and image vulnerability scanning.
#   1. npm audit for production dependencies
#   2. Trivy scan of the built image (OS packages + node_modules), failing on HIGH/CRITICAL
# Trivy runs from its official image and scans a saved tarball, so neither a local install nor
# access to the Docker socket is needed.
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."

# Pinned by digest like the base images: this image runs in CI with the source checked out.
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c}"
IMAGE="${1:-pushgate:scan}"
WORK="$(mktemp -d)"
command -v cygpath >/dev/null && WORK="$(cygpath -m "$WORK")"
trap 'rm -rf "$WORK"' EXIT

echo "== npm audit (production dependencies)"
npm audit --omit=dev --audit-level=low

echo "== docker build $IMAGE"
docker build -q -t "$IMAGE" . >/dev/null
docker save -o "$WORK/image.tar" "$IMAGE"

echo "== trivy $IMAGE"
docker run --rm -v "$WORK:/scan:ro" -v pushgate-trivy-cache:/root/.cache/ \
  "$TRIVY_IMAGE" image --input /scan/image.tar --scanners vuln \
  --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1
