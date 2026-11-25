#!/usr/bin/env python3
"""SSH sink: thin entrypoint; profiles in guards, actions in executors."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from passbolt_sinkkit.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main("ssh"))
