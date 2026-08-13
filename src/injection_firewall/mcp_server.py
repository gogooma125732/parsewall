"""Optional local stdio MCP facade with a root-confined file capability."""

import os
from pathlib import Path

from mcp.server import MCPServer

from .contract import RiskLevel
from .engine import ScanArtifacts, scan_file
from .worker import executable_policy_from_environment

server = MCPServer("document-injection-firewall")


def _input_root() -> Path:
    configured = os.environ.get("DIF_MCP_INPUT_ROOT")
    return Path(configured).resolve(strict=True) if configured else Path.cwd().resolve(strict=True)


def _confined_source(file_path: str) -> Path:
    root = _input_root()
    source = Path(file_path)
    if not source.is_absolute():
        source = root / source
    resolved = source.resolve(strict=True)
    if not resolved.is_relative_to(root) or source.is_symlink() or not resolved.is_file():
        raise PermissionError("file is outside the configured input root")
    return resolved


def inspect_path(file_path: str) -> ScanArtifacts:
    return scan_file(_confined_source(file_path), executables=executable_policy_from_environment())


@server.tool()
def inspect_file(file_path: str) -> dict[str, object]:
    """Inspect one root-confined document and return only the closed result schema."""
    return inspect_path(file_path).result.to_public_dict()


@server.tool()
def read_low_derivative(file_path: str) -> str:
    """Rescan and return marked plain text only when the current bytes are low risk."""
    artifacts = inspect_path(file_path)
    if artifacts.result.risk_level is not RiskLevel.LOW or artifacts.derivative_text is None:
        raise PermissionError("document is not releasable")
    return artifacts.derivative_text


def main() -> None:
    server.run(transport="stdio")
