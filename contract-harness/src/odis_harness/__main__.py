"""Allow `python -m odis_harness ...` invocations."""

from __future__ import annotations

import sys

from odis_harness.cli import main

if __name__ == "__main__":
    sys.exit(main())
