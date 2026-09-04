# Docker Compose local installation

## Requirements

- Docker Desktop or Docker Engine with Compose v2
- At least 1 GB of free memory and 1 GB of free disk space
- A free local TCP port (default `8000`)

## Install

```sh
./scripts/install-local.sh
```

The installer creates a private `.env`, builds the pinned `1.0.0` image, starts
the API and network-disabled worker, then verifies the security-critical
container settings. Open `http://127.0.0.1:8000/` after it passes.

The API binds to loopback by default. Do not set `DIF_BIND_ADDRESS=0.0.0.0`
unless an authenticated TLS reverse proxy and request limits are in place.

## Operate

```sh
docker compose ps
docker compose logs -f
./scripts/verify-local.sh
./scripts/uninstall-local.sh
```

Stopping the stack preserves the named jobs volume. Removing the volume is an
explicit destructive operation and is intentionally not part of the uninstall
script.
