#!/usr/bin/env bash

# 2026-11-15: REV01 - Introduce a consistent production Compose entry point.
# 2026-11-15: REV02 - Add stable image tags for backend and frontend builds.
# Preserve HTTPS, networking, authentication, and CA DNS overrides.
# Rollback: Restore REV01 or stop using this wrapper.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

COMPOSE_FILES=(
  docker-compose.yml
  docker-compose.https.yml
  docker-compose.network-candidate.yml
  docker-compose.auth-release.yml
  compose.ca-dns.yaml
  compose.image-tags.yaml
)

ARGS=()

for file in "${COMPOSE_FILES[@]}"; do
  if [[ ! -f "$SCRIPT_DIR/$file" ]]; then
    printf 'ERROR: Missing Compose file: %s\n' "$file" >&2
    exit 1
  fi

  ARGS+=(-f "$file")
done

cd "$SCRIPT_DIR"

exec docker compose "${ARGS[@]}" "$@"
