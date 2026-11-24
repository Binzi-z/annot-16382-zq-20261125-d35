"""Alternate entry point: ``python solution.py [--quick]``.

Delegates to :mod:`run_all`, which runs the complete offline verification and
writes ``REPORT.md`` + ``artifacts/verification_report.json``.
"""

from __future__ import annotations

import sys

from run_all import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
