"""Local command-line adapter for the closed scanner result contract."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

from .derivative import (
    compact_result_json,
    publish_result,
    quarantine_result,
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
    """Reject canonical, hard-link, and fixed-slot aliases before scanning."""
    try:
        if result_path.is_symlink() or result_path.resolve(strict=False) in {
            input_path.resolve(strict=False),
            (output_dir / "result.json").resolve(strict=False),
            (output_dir / "visible.txt").resolve(strict=False),
        }:
            return False
        if result_path.exists() and input_path.exists() and result_path.samefile(input_path):
            return False
    except OSError:
        return False
    return True


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _arguments(argv)
    except (SystemExit, ValueError):
        sys.stderr.write("scan arguments invalid\n")
        return 2
    if not _result_destination_is_safe(args.input, args.output_dir, args.result):
        sys.stderr.write("scan output failed\n")
        return 1
    try:
        artifacts = scan_file(args.input, args.output_dir, ScanLimits())
    except Exception:  # noqa: BLE001 -- CLI boundary is deliberately opaque.
        sys.stderr.write("scan failed\n")
        return 1
    try:
        write_result(args.result, artifacts.result)
    except Exception:  # noqa: BLE001 -- user-facing diagnostics must stay source-free.
        try:
            publish_result(args.output_dir, quarantine_result(), None)
        except Exception:  # noqa: BLE001, S110 -- diagnostics cannot expose recovery details.
            pass
        sys.stderr.write("scan output failed\n")
        return 1
    try:
        sys.stdout.buffer.write(compact_result_json(artifacts.result))
    except Exception:  # noqa: BLE001 -- stdout failures must not leak context.
        sys.stderr.write("scan output failed\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
