"""SSH guard: profiles, argv allowlist, upload containment and size limits."""

from __future__ import annotations

import json
import os
import posixpath
import re
import stat
from pathlib import Path
from typing import Any

from passbolt_sinkkit.errors import Denied, JobError

MAX_COMMANDS = 20
MAX_ARGS = 64
MAX_ARG_BYTES = 4_096
MAX_UPLOADS = 20
MAX_PROFILE_BYTES = 262_144
MAX_UPLOAD_DEFAULT = 10 * 1024 * 1024
PROFILE_NAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}")


def _posix_mode_gate() -> bool:
    """POSIX mode bits gate custody on Linux; Windows relies on the profile's ACLs.

    This is a named seam, not a global ``os.name`` check, so the behaviour can be exercised
    in tests without pretending the whole interpreter is Windows.
    """
    return os.name != "nt"


def load_profiles(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    file = Path(path)
    try:
        info = file.lstat()
    except OSError as exc:
        raise Denied("profiles file is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PROFILE_BYTES:
        raise Denied("profiles file is invalid")
    if _posix_mode_gate() and info.st_mode & 0o077:
        raise Denied("profiles file permissions are unsafe")
    try:
        document = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Denied("profiles file is invalid") from exc
    if not isinstance(document, dict) or not isinstance(document.get("profiles"), dict):
        raise Denied("profiles file is invalid")
    return document["profiles"]


def argv(value: Any) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_ARGS:
        raise JobError("command must be a non-empty argv array")
    parsed: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or len(item.encode("utf-8")) > MAX_ARG_BYTES:
            raise JobError("command argument is invalid")
        parsed.append(item)
    return parsed


def remote_path(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/") or ".." in Path(value).parts:
        raise JobError("remote path must be absolute and free of '..'")
    normalized = posixpath.normpath(value)
    if normalized != value or normalized == "/":
        raise JobError("remote path must be normalized and not root")
    return value


def under(path: str, roots: list[str]) -> bool:
    return any(path == root or path.startswith(root.rstrip("/") + "/") for root in roots)


def local_path(value: str, upload_root: Path) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = upload_root / candidate
    resolved = candidate.resolve()
    root = upload_root.resolve()
    if resolved != root and root not in resolved.parents:
        raise Denied("local upload is outside the staging directory")
    try:
        info = resolved.lstat()
    except OSError as exc:
        raise Denied("local upload is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise Denied("local upload is not a regular file")
    return resolved


def validate_ssh_job(
    job: object, *, adhoc: bool, profiles: dict[str, Any] | None = None
) -> dict[str, Any]:
    if not isinstance(job, dict):
        raise JobError("job must be an object")
    allowed = {"version", "sink", "profile", "commands", "uploads", "allow_overwrite"}
    if set(job) - allowed:
        raise JobError("job contains unsupported fields")
    if job.get("version") != 1:
        raise JobError("job version must be 1")
    expected_sink = "ssh_adhoc" if adhoc else "ssh_ops"
    if job.get("sink") != expected_sink:
        raise JobError("job belongs to another sink")
    profile_name = job.get("profile")
    profile: dict[str, Any] | None = None
    if profile_name is not None:
        if not isinstance(profile_name, str) or PROFILE_NAME_RE.fullmatch(profile_name) is None:
            raise JobError("profile name is invalid")
        if not profiles or profile_name not in profiles:
            raise Denied("profile is not registered")
        candidate = profiles[profile_name]
        if not isinstance(candidate, dict):
            raise JobError("profile is invalid")
        profile = candidate
    elif not adhoc:
        raise JobError("profile is required")
    commands = job.get("commands", [])
    if not isinstance(commands, list) or len(commands) > MAX_COMMANDS:
        raise JobError("commands are invalid")
    parsed_commands = [argv(item) for item in commands]
    uploads = job.get("uploads", [])
    if not isinstance(uploads, list) or len(uploads) > MAX_UPLOADS:
        raise JobError("uploads are invalid")
    parsed_uploads = []
    for item in uploads:
        if not isinstance(item, dict) or set(item) != {"local", "remote"}:
            raise JobError("upload entry is invalid")
        parsed_uploads.append({"local": str(item["local"]), "remote": remote_path(item["remote"])})
    if parsed_uploads and profile is None:
        raise Denied("uploads require a profile with allowed directories")
    allow_overwrite = job.get("allow_overwrite", False)
    if not isinstance(allow_overwrite, bool):
        raise JobError("allow_overwrite must be boolean")
    if profile is not None:
        if not allow_overwrite:
            allow_overwrite = bool(profile.get("allow_overwrite", False))
        allow_sudo = bool(profile.get("allow_sudo", False))
        if not adhoc:
            allowed_commands = {tuple(argv(item)) for item in profile.get("commands", [])}
            for command in parsed_commands:
                if tuple(command) not in allowed_commands:
                    raise Denied("command is not allowed by the profile")
        for command in parsed_commands:
            if command[0] == "sudo" and not allow_sudo:
                raise Denied("sudo is not allowed by the profile")
        roots = profile.get("upload_dirs", [])
        if not isinstance(roots, list) or not all(
            isinstance(item, str) and item.startswith("/") for item in roots
        ):
            raise Denied("profile upload_dirs are invalid")
        for upload in parsed_uploads:
            if not under(upload["remote"], roots):
                raise Denied("upload destination is not allowed by the profile")
    return {
        "profile": profile_name,
        "commands": parsed_commands,
        "uploads": parsed_uploads,
        "allow_overwrite": allow_overwrite,
        "max_bytes": int((profile or {}).get("max_bytes", MAX_UPLOAD_DEFAULT)),
    }
