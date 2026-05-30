#!/usr/bin/env python3
"""Inspect the random plugin FilterManager state in a full-memory minidump."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from dynamic_capture.filter_manager_dump import inspect_filter_manager


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", type=Path)
    parser.add_argument("--manager-slot-rva", type=lambda s: int(s, 0), default=0xAC9AC)
    parser.add_argument("--out-prefix", type=Path)
    args = parser.parse_args()
    inspect_filter_manager(args.dump, args.manager_slot_rva, args.out_prefix)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
