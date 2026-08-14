<p align="center">
  <img src="https://raw.githubusercontent.com/gogooma125732/parsewall/main/assets/parsewall-logo.png" alt="Parsewall" width="560">
</p>

<h1 align="center">Parsewall</h1>

<p align="center"><strong>Make every file inert before it reaches the model.</strong></p>

<p align="center">
  <img alt="Release v0.1.0" src="https://img.shields.io/badge/release-v0.1.0-EF4444?style=for-the-badge">
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-F59E0B?style=for-the-badge&logo=python&logoColor=white">
  <img alt="Docker Compose ready" src="https://img.shields.io/badge/docker-compose_ready-2496ED?style=for-the-badge&logo=docker&logoColor=white">
</p>

<p align="center">
  <img alt="Fail closed" src="https://img.shields.io/badge/policy-fail_closed-DC2626?style=flat-square">
  <img alt="Network-isolated worker" src="https://img.shields.io/badge/worker-network_isolated-7C3AED?style=flat-square">
  <img alt="Fixed JSON result" src="https://img.shields.io/badge/output-fixed_JSON-0891B2?style=flat-square">
</p>

<p align="center">
  <a href="#run-the-isolated-http-product">Quick start</a> ·
  <a href="https://github.com/gogooma125732/parsewall/blob/main/deploy/LOCAL_INSTALL.md">Local install</a> ·
  <a href="https://github.com/gogooma125732/parsewall/blob/main/deploy/OFFLINE_INSTALL.md">Offline install</a> ·
  <a href="https://github.com/gogooma125732/parsewall/blob/main/deploy/CODEX_PLUGIN.md">Codex plugin</a>
</p>

Parsewall is a deterministic, fail-closed pre-LLM scanner for untrusted
uploaded documents.
It never asks an LLM to decide whether a document is safe. It parses bounded
structures, renders visual formats, compares OCR with embedded text, and returns
only this public result contract:

```json
{
  "risk_level": "low | review | quarantine",
  "evidence": [],
  "location": [],
  "structural_anomalies": []
}
```

Even a `low` result does not make document content trusted. A low-only plain
UTF-8 derivative is prefixed with an untrusted-data marker and must remain data,
never an instruction source.

## Install the Python CLI

```sh
python -m pip install parsewall
parsewall scan --input ./report.txt
```

The package also installs `parsewall-api`, `parsewall-worker`, and
`parsewall-mcp`. The original `document-firewall*` commands remain available as
compatibility aliases.

## Run the isolated HTTP product

```sh
docker compose up --build
curl -F file=@report.pdf http://127.0.0.1:8000/v1/scans
```

Open `http://127.0.0.1:8000/` for the local browser upload interface. It
uploads one supported file, follows the isolated worker status, displays only
the fixed public result fields, and exposes a derivative download only for
`low` results. The interactive OpenAPI explorer remains at `/docs`.

For the versioned one-command installation and operational checks, see
[`deploy/LOCAL_INSTALL.md`](https://github.com/gogooma125732/parsewall/blob/main/deploy/LOCAL_INSTALL.md).

The API only accepts uploads and serves status/results. A separate worker scans
jobs with no network, a read-only root filesystem, no Linux capabilities, and
bounded CPU, memory, processes, and temporary storage.

Endpoints:

- `POST /v1/scans`
- `GET /v1/scans/{job_id}`
- `GET /v1/scans/{job_id}/result`
- `GET /v1/scans/{job_id}/derivative` (low results only)

Supported inputs are UTF-8/UTF-16 text, Markdown, HTML, DOCX, PPTX, XLSX, PDF,
PNG, and JPEG. Unsupported, corrupt, encrypted, incomplete, or dependency-
blocked scans fail closed.

## Build distribution artifacts

Build the four distribution channels in order after the versioned Docker image
exists locally:

```sh
python3 scripts/build_release.py --channel all --clean
```

Artifacts are written under `dist/releases/<version>/` with SHA-256 hashes and
a machine-readable release manifest:

1. source-backed Docker Compose local installer (`*-compose.tar.gz`);
2. architecture-specific offline Docker bundle (`*-offline-<platform>.tar`);
3. Python wheel and sdist (`python/`);
4. standalone Codex plugin and local marketplace ZIP files.

Installation details are in [`deploy/LOCAL_INSTALL.md`](https://github.com/gogooma125732/parsewall/blob/main/deploy/LOCAL_INSTALL.md),
[`deploy/OFFLINE_INSTALL.md`](https://github.com/gogooma125732/parsewall/blob/main/deploy/OFFLINE_INSTALL.md),
[`deploy/PYTHON_CLI.md`](https://github.com/gogooma125732/parsewall/blob/main/deploy/PYTHON_CLI.md), and
[`deploy/CODEX_PLUGIN.md`](https://github.com/gogooma125732/parsewall/blob/main/deploy/CODEX_PLUGIN.md).

## Codex plugin and MCP

The distributable plugin is under `plugins/document-injection-firewall`. It
contains the `inspect-untrusted-files` skill, a `PreToolUse` hook that blocks
local raw-document reads, and an optional root-confined stdio MCP service.

Codex's current `UserPromptSubmit` hook schema exposes prompt text but not an
attachment list, so the hook cannot claim to intercept native attachment
ingestion. It is a local-tool guardrail; the skill and MCP workflow remain the
mandatory pre-read gate.
