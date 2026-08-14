# Offline Docker installation

This bundle is architecture-specific. Its filename records the target platform,
for example `linux-arm64`. Build a separate bundle for each required platform.

## Transfer and verify

Transfer the complete extracted directory into the offline environment. Do not
rename or modify individual files before verification.

```sh
./install.sh
```

The installer verifies `SHA256SUMS`, loads `image.tar.gz` without accessing a
registry, starts `compose.yaml` with `pull_policy: never`, and checks the API and
worker isolation settings.

## Operate

```sh
./verify.sh
docker compose --env-file .env -f compose.yaml ps
docker compose --env-file .env -f compose.yaml logs -f
./uninstall.sh
```

The uninstall script preserves job data. Volume deletion remains an explicit,
separate destructive operation.
