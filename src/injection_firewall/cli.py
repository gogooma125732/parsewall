"""Local command-line adapter for the closed scanner result contract."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .derivative import compact_result_json, write_result
from .engine import scan_file
from .limits import ScanLimits


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="document-firewall")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("--input", type=Path, required=True)
    scan.add_argument("--output-dir", type=Path, required=True)
    scan.add_argument("--result", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _arguments(argv)
    artifacts = scan_file(args.input, args.output_dir, ScanLimits())
    try:
        write_result(args.result, artifacts.result)
    except Exception:  # noqa: BLE001 -- user-facing diagnostics must stay source-free.
        sys.stderr.write("scan output failed\n")
        return 1
    sys.stdout.buffer.write(compact_result_json(artifacts.result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
