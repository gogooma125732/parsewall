"""Local command-line adapter for the closed scanner result contract."""

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

from .derivative import (
    close_installed_result,
    close_publication,
    compact_result_json,
    destination_available,
    installed_result_is_current,
    publication_is_current,
    revoke_installed_result,
    revoke_publication,
    write_result,
)
from .engine import scan_file
from .limits import ScanLimits


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError("invalid arguments")


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = _ArgumentParser(prog="document-firewall", add_help=False)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("--input", type=Path, required=True)
    scan.add_argument("--output-dir", type=Path, required=True)
    scan.add_argument("--result", type=Path, required=True)
    return parser.parse_args(argv)


def _result_destination_is_safe(input_path: Path, output_dir: Path, result_path: Path) -> bool:
    """Reject occupied targets and lexical overlap before any scan side effect."""
    try:
        output_absolute = os.path.abspath(os.fspath(output_dir))
        result_absolute = os.path.abspath(os.fspath(result_path))
        if result_absolute == output_absolute or result_absolute.startswith(output_absolute + os.sep):
            return False
        if not destination_available(output_dir) or not destination_available(result_path):
            return False
    except (OSError, ValueError):
        return False
    return True


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _arguments(argv)
    except (SystemExit, ValueError):
        sys.stderr.write("scan arguments invalid\n")
        return 2
    installed_result = None
    artifacts = None
    try:
        if not _result_destination_is_safe(args.input, args.output_dir, args.result):
            raise ValueError("unsafe output")
        artifacts = scan_file(args.input, args.output_dir, ScanLimits())
        installed_result = write_result(args.result, artifacts.result)
        if not publication_is_current(artifacts._publication) or not installed_result_is_current(
            installed_result
        ):
            raise OSError("public output changed")
        payload = compact_result_json(artifacts.result)
        written = 0
        while written < len(payload):
            count = sys.stdout.buffer.write(payload[written:])
            if count is None or count <= 0:
                raise OSError("stdout write failed")
            written += count
        sys.stdout.buffer.flush()
    except Exception:  # noqa: BLE001 -- public CLI boundary must stay source-free.
        revoke_installed_result(installed_result)
        revoke_publication(artifacts._publication if artifacts is not None else None)
        sys.stderr.write("scan output failed\n")
        return 1
    close_installed_result(installed_result)
    close_publication(artifacts._publication if artifacts is not None else None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
