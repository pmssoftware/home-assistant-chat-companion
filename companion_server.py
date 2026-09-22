#!/usr/bin/env python3
"""Run the companion server directly from a source checkout."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from hachat_companion.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())

