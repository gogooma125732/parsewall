#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RELEASE_CACHE=${TMPDIR:-/tmp}/dif-release-uv-cache
export UV_CACHE_DIR="$RELEASE_CACHE"
cd "$PROJECT_DIR"

uv run ruff check .
uv run mypy src
uv run pytest tests/unit tests/integration -q
docker compose config --quiet
docker compose -f deploy/offline-compose.yaml config --quiet
uv run --with pyyaml python \
    /Users/nayeonggo/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py \
    plugins/document-injection-firewall
uv run --with pyyaml python \
    /Users/nayeonggo/.codex/skills/.system/skill-creator/scripts/quick_validate.py \
    plugins/document-injection-firewall/skills/inspect-untrusted-files
python3 scripts/build_release.py --channel all --clean

version=$(python3 -c "import pathlib,tomllib; print(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['version'])")
cd "dist/releases/$version"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS
else
    LC_ALL=C shasum -a 256 -c SHA256SUMS
fi

printf '%s\n' "Release verification passed."
