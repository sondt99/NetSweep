#!/usr/bin/env python3
"""NetSweep launcher — thin entrypoint into the netsweep package.

Usage:
  python run.py
  python -m netsweep
  netsweep
"""
from __future__ import annotations

import sys
from pathlib import Path

# Allow running from a git checkout without install: put repo root on sys.path
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from netsweep.cli.menu import main


if __name__ == "__main__":
    main()
