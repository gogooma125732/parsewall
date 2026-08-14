# Parsewall Codex plugin

This plugin adds the `inspect-untrusted-files` skill, a fail-closed
`PreToolUse` hook, and a local stdio MCP server. Install the matching Python
wheel first so `document-firewall-mcp` is available on `PATH`.

The MCP service reads only files under `DIF_MCP_INPUT_ROOT` (or its working
directory when unset). Set that root narrowly before starting Codex. Start a
new task after plugin installation so Codex loads the skill, hook, and tools.

The hook guards observable tool calls. It does not claim to intercept every
native attachment-ingestion path, so the skill workflow remains mandatory.
