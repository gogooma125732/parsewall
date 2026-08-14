#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

# Preserve the jobs volume. Delete it only with an explicit Compose --volumes command.
docker compose --env-file .env -f compose.yaml down
