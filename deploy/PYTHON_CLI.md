# Python CLI and wheel

The wheel provides these console commands:

- `parsewall`
- `parsewall-api`
- `parsewall-worker`
- `parsewall-mcp`

The original `document-firewall*` commands remain compatibility aliases:

- `document-firewall`
- `document-firewall-api`
- `document-firewall-worker`
- `document-firewall-mcp`

Install the wheel in a dedicated Python 3.11+ environment. For example:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install parsewall-0.1.0-py3-none-any.whl
parsewall scan --input ./report.txt
```

The scanner emits only the fixed four-field JSON result on stdout. A marked
derivative is available only through a caller-created, empty, mode-`0600` file
descriptor passed with `--derivative-fd`.

PDF/image OCR and Office rendering require the system executables `tesseract`
and `libreoffice`. Missing dependencies fail closed; they do not downgrade the
result. The Docker distribution includes both dependencies.
