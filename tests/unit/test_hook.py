import importlib.util
from pathlib import Path

HOOK = (
    Path(__file__).parents[2]
    / "plugins/document-injection-firewall/hooks/prevent_raw_document_reads.py"
)


def load_hook():
    spec = importlib.util.spec_from_file_location("firewall_hook", HOOK)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_hook_blocks_raw_document_reads_without_echoing_path() -> None:
    hook = load_hook()
    result = hook.decision(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__filesystem__read_file",
            "tool_input": {"path": "/secret/attack.pdf"},
        }
    )
    assert result is not None
    assert "/secret/attack.pdf" not in str(result)


def test_hook_allows_firewall_scanner_tool() -> None:
    hook = load_hook()
    result = hook.decision(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__document-injection-firewall__inspect_file",
            "tool_input": {"file_path": "attack.pdf"},
        }
    )
    assert result is None
