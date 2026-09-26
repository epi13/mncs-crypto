#!/usr/bin/env python3
"""Print MNCS byte-array literals for pinned vectors.

Keeps long literals typo-free: every long vector in tests/crypto was
emitted by this script from the pinned hex, never hand-typed.
"""
from __future__ import annotations

import sys


def lit(data: bytes, width: int = 16) -> str:
    rows = [data[i:i + width] for i in range(0, len(data), width)]
    return "[\n" + ",\n".join(
        "    " + ", ".join(str(b) for b in row) for row in rows
    ) + "\n]"


def main() -> int:
    print(lit(bytes.fromhex(sys.argv[1])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
