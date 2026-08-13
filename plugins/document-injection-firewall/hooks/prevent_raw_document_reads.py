#!/usr/bin/env python3
"""Fail-closed PreToolUse guardrail for raw document paths."""

import json
import re
import sys
from collections.abc import Iterator
from typing import Any

_DOCUMENT = re.compile(
    r"(?:^|[\s'\"=:/])[^\s'\"=]*\.(?:txt|md|markdown|html?|docx|pptx|xlsx|pdf|png|jpe?g)(?:$|[\s'\";,)])",
    re.IGNORECASE,
)
_SCANNER_TOOLS = frozenset(
    {
        "mcp__document-injection-firewall__inspect_file",
        "mcp__document-injection-firewall__read_low_derivative",
        "mcp__document_injection_firewall__inspect_file",
        "mcp__document_injection_firewall__read_low_derivative",
    }
)
_SCANNER_COMMANDS = frozenset({"document-firewall", "document-firewall-mcp"})


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _deny() -> dict[str, object]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "Raw document access blocked; inspect it with Document Injection Firewall first.",
        }
    }


def decision(payload: object) -> dict[str, object] | None:
    if not isinstance(payload, dict) or payload.get("hook_event_name") != "PreToolUse":
        return _deny()
    tool_name = payload.get("tool_name")
    if tool_name in _SCANNER_TOOLS:
        return None
    strings = tuple(_strings(payload.get("tool_input")))
    if tool_name == "Bash" and any(
        command in item for command in _SCANNER_COMMANDS for item in strings
    ):
        return None
    if any(_DOCUMENT.search(item) for item in strings):
        return _deny()
    return None


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        output = _deny() if len(raw) > 1024 * 1024 else decision(json.loads(raw))
    except Exception:  # noqa: BLE001 -- malformed hook input must fail closed.
        output = _deny()
    if output is not None:
        sys.stdout.write(json.dumps(output, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
