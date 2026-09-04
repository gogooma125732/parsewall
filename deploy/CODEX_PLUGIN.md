# Codex Plugin, Hook, and MCP

Install Parsewall as an isolated Python tool so `parsewall-mcp` is on the
process `PATH`. Add the GitHub repository as a Codex marketplace and install
the plugin:

```sh
uv tool install parsewall==1.0.0
codex plugin marketplace add gogooma125732/parsewall --ref main
codex plugin add document-injection-firewall@parsewall
```

For an offline or pinned install, extract
`parsewall-codex-marketplace-1.0.0.zip`, then use the extracted root instead:

```sh
codex plugin marketplace add /absolute/path/to/parsewall-marketplace
codex plugin add document-injection-firewall@parsewall-local
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
