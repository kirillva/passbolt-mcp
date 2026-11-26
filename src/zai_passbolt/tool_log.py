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
    """Address of a site hint: scheme and host:port stay, credentials/path/query go.

    The scheme is what distinguishes "the record is http" from "the model typed
    https", which is exactly the class of mistake the guides have to explain.
    """
    text = value.strip()
    has_scheme = "://" in text
    candidate = text if has_scheme else f"https://{text}"
    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").rstrip(".")
        port = parsed.port
    except ValueError:
        return "<unparsable>"
    if not host:
        return "<unparsable>"
    authority = f"{host}:{port}" if port else host
    if not has_scheme:
        return authority
    scheme = parsed.scheme if parsed.scheme in {"http", "https", "ssh", "postgres"} else "<scheme>"
    return f"{scheme}://{authority}"


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


def _append(path: Path, entry: dict[str, Any]) -> None:
    """Append one bounded line; drop bulky sections rather than truncate the JSON."""
    line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
    if len(line.encode("utf-8")) > MAX_LINE_BYTES:
        for key in ("arguments", "changes"):
            entry.pop(key, None)
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _rotate(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, (line + "\n").encode("utf-8"))
    finally:
        os.close(descriptor)


def record_error(
    *,
    state_path: Path,
    version: str,
    tool: str,
    outcome: str,
    code: str,
    error: str | None,
    hint: str | None,
    detail: str | None = None,
    actor: str | None,
    execution_id: str | None,
    duration_ms: int,
    arguments: dict[str, Any],
) -> None:
    """Append one bounded JSON line. Any failure here is swallowed on purpose."""
    if not enabled():
        return
    try:
        _append(
            log_path(state_path),
            {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "version": version,
                "tool": _safe_text(tool, 64),
                "outcome": _safe_text(outcome, 24),
                "code": _safe_text(code, 64),
                "error": _safe_text(error, 64),
                "hint": _safe_text(hint, 400),
                "detail": _safe_text(detail, 300),
                "actor": _safe_text(actor, 128),
                "execution_id": _safe_text(execution_id, 64),
                "duration_ms": int(duration_ms),
                "arguments": summarize_arguments(arguments),
            },
        )
    except (OSError, ValueError, TypeError):
        return


CHANGES_NAME = "data-changes.jsonl"
# Values worth reading in a change log; secrets are reduced to their shape instead.
SAFE_CHANGE_TEXT = frozenset(
    {"name", "uri", "username", "permission", "share_mode", "folder", "parent", "resource_id", "folder_id"}
)


def changes_path(state_path: Path) -> Path:
    """`<state dir>/data-changes.jsonl`, or an operator-chosen file inside their home."""
    override = os.environ.get("PASSBOLT_CHANGE_LOG_PATH", "").strip()
    if override:
        candidate = Path(override).expanduser()
        if candidate.is_absolute() and ".." not in candidate.parts:
            try:
                candidate.relative_to(Path.home())
            except ValueError:
                return Path(state_path).parent / CHANGES_NAME
            return candidate
    return Path(state_path).parent / CHANGES_NAME


def summarize_changes(arguments: dict[str, Any]) -> dict[str, Any]:
    """What a write asked to change: text fields as-is, secrets as shape only."""
    summary: dict[str, Any] = {}
    for key in sorted(SAFE_CHANGE_TEXT):
        value = arguments.get(key)
        if isinstance(value, str) and value:
            summary[key] = _safe_text(value, 200)
    for key in ("share_with_users", "share_with_groups", "groups", "users"):
        value = arguments.get(key)
        if isinstance(value, list):
            summary[key] = {"items": len(value)}
    source = arguments.get("secret_source")
    if isinstance(source, dict):
        summary["secret_source"] = {"kind": _safe_text(source.get("kind"), 32)}
    fields = arguments.get("fields")
    if isinstance(fields, dict):
        requested: dict[str, Any] = {}
        for key, value in sorted(fields.items()):
            if key in SAFE_CHANGE_TEXT and isinstance(value, str):
                requested[key] = _safe_text(value, 200)
            elif key in {"description", "note"}:
                requested[key] = {"chars": len(value)} if isinstance(value, str) else None
            elif key == "secret_source" and isinstance(value, dict):
                requested[key] = {"kind": _safe_text(value.get("kind"), 32)}
            else:
                kind = "object" if isinstance(value, dict) else "list" if isinstance(value, list) else "value"
                requested[key] = {"kind": kind}
        summary["fields"] = requested
    return summary


def record_change(
    *,
    state_path: Path,
    version: str,
    tool: str,
    operation: str,
    outcome: str,
    approval: str,
    actor: str | None,
    execution_id: str | None,
    duration_ms: int,
    arguments: dict[str, Any],
    result: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    """Append one applied change. Never the secret, never the note body."""
    if not enabled():
        return
    try:
        stored = result if isinstance(result, dict) else {}
        summary = {
            key: stored[key]
            for key in ("resource_id", "folder_id", "created", "updated", "shared", "idempotent")
            if key in stored and isinstance(stored[key], (str, bool, int))
        }
        _append(
            changes_path(state_path),
            {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "version": version,
                "tool": _safe_text(tool, 64),
                "operation": _safe_text(operation, 64),
                "outcome": _safe_text(outcome, 24),
                "approval": _safe_text(approval, 16),
                "actor": _safe_text(actor, 128),
                "execution_id": _safe_text(execution_id, 64),
                "duration_ms": int(duration_ms),
                "changes": summarize_changes(arguments),
                "result": summary,
                "error": _safe_text(error, 64),
            },
        )
    except (OSError, ValueError, TypeError):
        return
