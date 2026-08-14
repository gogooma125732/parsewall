# Codex Plugin, Hook, and MCP

Install the Python wheel first so `parsewall-mcp` is on the process
`PATH`. Then extract the marketplace archive and register its root:

```sh
codex plugin marketplace add /absolute/path/to/document-injection-firewall-marketplace
codex plugin add document-injection-firewall@document-injection-firewall-local
```

Start a new Codex task after installation. The plugin contains:

- `inspect-untrusted-files`, which requires deterministic inspection before any
  model or general tool reads a supported document;
- a fail-closed `PreToolUse` hook that blocks observable raw-document reads;
- a root-confined local stdio MCP server with `inspect_file` and
  `read_low_derivative` tools.

Set `DIF_MCP_INPUT_ROOT` to the narrowest directory containing files intended
for scanning before starting Codex. If unset, the MCP process confines itself
to its working directory. The hook is defense in depth and cannot claim to
intercept every native attachment-ingestion path.
