#!/usr/bin/env python3
"""Local error log for tool calls.

The log exists so an operator can improve the agent instructions from real
failures: which tool the model called, which safe error code came back, which
argument shape it passed. It never records a secret — no password, no
secret_source, no note, no provider message, no path — only our own
configuration hint and a whitelisted argument summary. It is append-only JSONL,
0600, rotated by size, and a broken log never breaks a tool call.
"""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MAX_LINE_BYTES = 2_000
MAX_FILE_BYTES = 2 * 1024 * 1024
ROTATED_FILES = 2
DEFAULT_NAME = "tool-errors.jsonl"
DISABLED_VALUES = frozenset({"0", "off", "false", "no", "none"})

# Fixed-length or non-secret arguments worth reading when an instruction is wrong.
SAFE_TEXT_ARGUMENTS = frozenset(
    {
        "target_url",
        "query",
        "username",
        "sink_ref",
        "page",
        "resource_id",
        "folder_id",
        "job_ref",
        "approval_id",
        "expected_modified",
        "tool",
        "direction",
        "share_mode",
    }
)
# Values that may hold a secret or a private note: only their shape is recorded.
NEVER_LOGGED_KEYS = frozenset({"secret_source", "secret", "password", "note", "token", "fields", "uris"})


def enabled() -> bool:
    return os.environ.get("PASSBOLT_TOOL_LOG", "").strip().lower() not in DISABLED_VALUES


def log_path(state_path: Path) -> Path:
    """`<state dir>/tool-errors.jsonl`, or an operator-chosen file inside their home."""
    override = os.environ.get("PASSBOLT_TOOL_LOG_PATH", "").strip()
    if override:
        candidate = Path(override).expanduser()
        if candidate.is_absolute() and ".." not in candidate.parts:
            try:
                candidate.relative_to(Path.home())
            except ValueError:
                return Path(state_path).parent / DEFAULT_NAME
            return candidate
    return Path(state_path).parent / DEFAULT_NAME


def _safe_text(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    return text[:limit] if text else None


def safe_site(value: str) -> str:
    """Host and port of a site hint: credentials, path, query and fragment are dropped."""
    text = value.strip()
    candidate = text if "://" in text else f"https://{text}"
    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").rstrip(".")
        port = parsed.port
    except ValueError:
        return "<unparsable>"
    if not host:
        return "<unparsable>"
    return f"{host}:{port}" if port else host


def summarize_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Keep what a wrong instruction looks like; keep nothing that can be a secret."""
    summary: dict[str, Any] = {}
    for key in sorted(arguments):
        value = arguments[key]
        if key in NEVER_LOGGED_KEYS:
            continue
        if key == "target_url" and isinstance(value, str):
            summary[key] = safe_site(value)
        elif key in SAFE_TEXT_ARGUMENTS and isinstance(value, str):
            summary[key] = _safe_text(value, 120)
        elif value is None or isinstance(value, bool):
            summary[key] = value
        elif isinstance(value, int | float | str):
            summary[key] = {"chars": len(value)} if isinstance(value, str) else value
        elif isinstance(value, dict):
            summary[key] = {"kind": "object", "fields": len(value)}
        elif isinstance(value, list | tuple):
            summary[key] = {"kind": "list", "items": len(value)}
    return summary


def _rotate(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        # A planted symlink must not become a write target; drop it and start over.
        path.unlink(missing_ok=True)
        return
    if info.st_size < MAX_FILE_BYTES:
        return
    for index in range(ROTATED_FILES, 0, -1):
        source = path if index == 1 else path.with_name(f"{path.name}.{index - 1}")
        target = path.with_name(f"{path.name}.{index}")
        try:
            os.replace(source, target)
        except FileNotFoundError:
            continue


def record_error(
    *,
    state_path: Path,
    version: str,
    tool: str,
    outcome: str,
    code: str,
    error: str | None,
    hint: str | None,
    actor: str | None,
    execution_id: str | None,
    duration_ms: int,
    arguments: dict[str, Any],
) -> None:
    """Append one bounded JSON line. Any failure here is swallowed on purpose."""
    if not enabled():
        return
    try:
        entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "version": version,
            "tool": _safe_text(tool, 64),
            "outcome": _safe_text(outcome, 24),
            "code": _safe_text(code, 64),
            "error": _safe_text(error, 64),
            "hint": _safe_text(hint, 400),
            "actor": _safe_text(actor, 128),
            "execution_id": _safe_text(execution_id, 64),
            "duration_ms": int(duration_ms),
            "arguments": summarize_arguments(arguments),
        }
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            # Drop the bulk, never truncate the JSON: a line has to stay parseable.
            entry["arguments"] = {}
            entry["hint"] = _safe_text(entry["hint"], 200)
            line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
        path = log_path(state_path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _rotate(path)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            os.write(descriptor, (line + "\n").encode("utf-8"))
        finally:
            os.close(descriptor)
    except (OSError, ValueError, TypeError):
        return
