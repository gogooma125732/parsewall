#!/usr/bin/env python3
"""Emit the firewall's closed JSON result for one local file."""

import argparse
import json
from pathlib import Path

from injection_firewall.engine import scan_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    result = scan_file(parser.parse_args().file).result
    print(json.dumps(result.to_public_dict(), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
