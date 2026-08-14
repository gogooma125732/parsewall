#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS
else
    shasum -a 256 -c SHA256SUMS
fi

gzip -dc image.tar.gz | docker image load
docker compose --env-file .env -f compose.yaml up -d --pull never
./verify.sh

port=$(sed -n 's/^DIF_PORT=//p' .env | tail -n 1)
printf '%s\n' "Parsewall is running at http://127.0.0.1:${port:-8000}/"
