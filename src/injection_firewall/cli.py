"""Local CLI with result-only stdout and optional capability-based derivative."""

import argparse
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import BinaryIO, NoReturn

from .derivative import compact_result_json
from .engine import scan_file


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError("invalid arguments")


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = _ArgumentParser(prog="document-firewall", add_help=False)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", add_help=False)
    scan.add_argument("--input", type=Path, required=True)
    scan.add_argument("--derivative-fd", type=int)
    return parser.parse_args(argv)


def _write_all(stream: BinaryIO, contents: bytes) -> None:
    written = 0
    while written < len(contents):
        count = stream.write(contents[written:])
        if count is None:
            count = len(contents) - written
        if count <= 0:
            raise OSError("short output write")
        written += count
    stream.flush()


def _write_derivative(descriptor: int, derivative: str) -> None:
    duplicate = os.dup(descriptor)
    try:
        info = os.fstat(duplicate)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != 0
        ):
            raise OSError("derivative capability invalid")
        contents = derivative.encode("utf-8")
        written = 0
        while written < len(contents):
            count = os.write(duplicate, contents[written:])
            if count <= 0:
                raise OSError("short derivative write")
            written += count
        os.fsync(duplicate)
        if os.fstat(duplicate).st_size != len(contents):
            raise OSError("derivative write invalid")
    finally:
        os.close(duplicate)


def _opaque_stderr(message: str) -> None:
    try:
        sys.stderr.write(message)
    except Exception:  # noqa: BLE001 -- diagnostics must not replace the original outcome.
        return


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _arguments(argv)
    except (SystemExit, ValueError, TypeError, OSError):
        _opaque_stderr("scan arguments invalid\n")
        return 2

    try:
        artifacts = scan_file(args.input)
        if args.derivative_fd is not None:
            if artifacts.derivative_text is None:
                raise OSError("derivative unavailable")
            _write_derivative(args.derivative_fd, artifacts.derivative_text)
        _write_all(sys.stdout.buffer, compact_result_json(artifacts.result))
        return 0
    except Exception:  # noqa: BLE001 -- CLI diagnostics are intentionally opaque.
        _opaque_stderr("scan failed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
