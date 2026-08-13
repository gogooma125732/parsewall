from pathlib import Path

import pytest

from injection_firewall.contract import RiskLevel
from injection_firewall.mcp_server import inspect_path


def test_mcp_is_confined_to_configured_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    source = root / "report.txt"
    source.write_text("ordinary report", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("ordinary report", encoding="utf-8")
    monkeypatch.setenv("DIF_MCP_INPUT_ROOT", str(root))
    assert inspect_path("report.txt").result.risk_level is RiskLevel.LOW
    with pytest.raises(PermissionError):
        inspect_path(str(outside))
