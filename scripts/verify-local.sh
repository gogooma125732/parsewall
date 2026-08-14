#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_DIR"

api_id=$(docker compose ps -q api)
worker_id=$(docker compose ps -q worker)
test -n "$api_id"
test -n "$worker_id"

attempt=0
while [ "$attempt" -lt 30 ]; do
    status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$api_id")
    if [ "$status" = healthy ]; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
test "$status" = healthy

test "$(docker inspect --format '{{.Config.User}}' "$api_id")" = "65532:65532"
test "$(docker inspect --format '{{.Config.User}}' "$worker_id")" = "65532:65532"
test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$api_id")" = true
test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$worker_id")" = true
test "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$worker_id")" = none

docker compose exec -T api python -c \
    "import json, urllib.request; assert json.load(urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)) == {'status': 'ok'}"

printf '%s\n' "Compose verification passed."
