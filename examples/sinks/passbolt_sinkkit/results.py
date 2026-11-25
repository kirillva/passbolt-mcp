"""Uniform, private result files shared by every sink."""

from __future__ import annotations

import contextlib
import json
import os
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

from passbolt_sinkkit.errors import exit_code_for


class Result:
    def __init__(self, directory: str | Path, sink: str, version: int = 1) -> None:
        self.directory = Path(directory)
        self.sink = sink
        self.version = version
        self.started = time.monotonic()
        self.payload: dict[str, Any] = {"status": "error", "sink": sink, "version": version}

    def update(self, **fields: Any) -> None:
        self.payload.update(fields)

    def write(self) -> Path:
        self.payload["duration_ms"] = int((time.monotonic() - self.started) * 1000)
        self.payload["exit_code"] = exit_code_for(str(self.payload.get("status")))
        self.directory.mkdir(mode=0o700, exist_ok=True)
        descriptor, raw = tempfile.mkstemp(prefix=f"{self.sink}-", suffix=".json", dir=self.directory)
        path = Path(raw)
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(self.payload, handle, ensure_ascii=False, indent=2, default=str)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            target = self.directory / f"{self.sink}-last.json"
            os.replace(path, target)
            return target
        finally:
            with contextlib.suppress(OSError):
                path.unlink()
