# Document Injection Firewall

A deterministic, fail-closed pre-LLM scanner for untrusted uploaded documents.
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

## Run the isolated HTTP product

```sh
docker compose up --build
curl -F file=@report.pdf http://127.0.0.1:8000/v1/scans
```

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
