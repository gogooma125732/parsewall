#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

cd "$PROJECT_DIR"
if [ ! -f .env ]; then
    cp .env.example .env
    chmod 600 .env
fi

docker compose build
docker compose up -d --pull never
"$SCRIPT_DIR/verify-local.sh"

printf '%s\n' "Document Injection Firewall is running at http://127.0.0.1:8000/"
