"""Envelope parsing: credentials plus the target derived from the record URI.

The server sends ``target`` (already resolved from the Passbolt resource URI)
and keeps ``target_url`` for backward compatibility. Sinks never trust a
caller-chosen target.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from passbolt_sinkkit.errors import InputError, TargetError

DATABASE_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_$.-]{0,62}")
PAGE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")
MAX_HOST = 253
MAX_PATH = 2_048


def page_marker(envelope: Any) -> str | None:
    """Non-secret tab marker; it selects a browser tab, never the target host."""
    if not isinstance(envelope, dict):
        return None
    value = envelope.get("page")
    if value is None:
        return None
    if not isinstance(value, str) or PAGE_RE.fullmatch(value) is None:
        raise InputError("page marker is invalid")
    return value


def credentials(envelope: Any) -> tuple[str, str]:
    if not isinstance(envelope, dict):
        raise InputError("envelope must be an object")
    username = envelope.get("username")
    password = envelope.get("password")
    if not isinstance(username, str) or not username:
        raise InputError("envelope has no username")
    if not isinstance(password, str) or not password:
        raise InputError("envelope has no password")
    return username, password


def _validate(target: dict[str, Any], *, default_port: int, default_database: str | None) -> dict:
    host = target.get("host")
    if not isinstance(host, str) or not host or len(host) > MAX_HOST:
        raise TargetError("target host is invalid")
    host = host.lower()
    port = target.get("port", default_port)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
        raise TargetError("target port is invalid")
    path = target.get("path") or "/"
    if not isinstance(path, str) or not path.startswith("/") or len(path) > MAX_PATH:
        raise TargetError("target path is invalid")
    database: str | None = None
    if default_database is not None:
        candidate = target.get("database") or path.strip("/") or default_database
        if not isinstance(candidate, str) or DATABASE_RE.fullmatch(candidate) is None:
            raise TargetError("target database is invalid")
        database = candidate
    return {
        "uri": str(target.get("uri") or ""),
        "host": host,
        "port": port,
        "path": path,
        "database": database,
    }


def parse_target(
    envelope: dict[str, Any], *, default_port: int, default_database: str | None = None
) -> dict[str, Any]:
    target = envelope.get("target")
    if isinstance(target, dict) and target.get("host"):
        return _validate(target, default_port=default_port, default_database=default_database)
    raw = envelope.get("target_url")
    if not isinstance(raw, str) or not raw:
        raise TargetError("target is missing")
    parsed = urlsplit(raw)
    if parsed.scheme != "https" or not parsed.hostname:
        raise TargetError("target URL is invalid")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise TargetError("target URL is invalid")
    fallback = {
        "uri": raw,
        "host": parsed.hostname,
        "port": parsed.port or default_port,
        "path": parsed.path or "/",
    }
    return _validate(fallback, default_port=default_port, default_database=default_database)
