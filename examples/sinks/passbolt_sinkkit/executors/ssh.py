"""SSH executor: paramiko connect, argv commands and staged SFTP uploads."""

from __future__ import annotations

import hashlib
import os
import shlex
import uuid
from pathlib import Path
from typing import Any

from passbolt_sinkkit.errors import Denied, RemoteFailure, TargetError
from passbolt_sinkkit.guards.ssh import local_path

MAX_OUTPUT_BYTES = 262_144


def _read_capped(stream, limit: int = MAX_OUTPUT_BYTES) -> tuple[str, bool]:
    data = stream.read(limit + 1)
    text = data[:limit].decode(errors="replace") if isinstance(data, bytes) else str(data)[:limit]
    return text, len(data) > limit


def _upload(sftp, upload: dict, upload_root: Path, job: dict) -> dict[str, Any]:
    source = local_path(upload["local"], upload_root)
    if source.stat().st_size > job["max_bytes"]:
        raise Denied("local upload exceeds the profile limit")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    destination = upload["remote"]
    if not job["allow_overwrite"]:
        try:
            sftp.stat(destination)
        except OSError:
            pass
        else:
            raise Denied("remote file exists and overwrite is disabled")
    temporary = f"{destination}.upload-{uuid.uuid4().hex}"
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        sftp.putfo(handle, temporary)
    try:
        sftp.posix_rename(temporary, destination)
    except OSError:
        sftp.rename(temporary, destination)
    return {
        "remote": destination,
        "status": "uploaded",
        "bytes": source.stat().st_size,
        "sha256": digest,
    }


def run(
    target: dict[str, Any],
    username: str,
    password: str,
    job: dict[str, Any],
    *,
    known_hosts: str,
    upload_root: Path,
) -> tuple[dict[str, Any], int]:
    try:
        import paramiko
    except ImportError as exc:
        raise RemoteFailure("paramiko is not installed") from exc
    client = paramiko.SSHClient()
    try:
        client.load_host_keys(known_hosts)
    except OSError as exc:
        raise Denied("known_hosts is unavailable") from exc
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            target["host"],
            port=target["port"],
            username=username,
            password=password,
            timeout=15,
            banner_timeout=15,
            auth_timeout=15,
            allow_agent=False,
            look_for_keys=False,
        )
    except Exception as exc:  # noqa: BLE001 - provider errors stay opaque
        raise TargetError("ssh connection failed") from exc
    exit_code = 0
    try:
        uploads: list[dict[str, Any]] = []
        sftp = client.open_sftp()
        try:
            for upload in job["uploads"]:
                try:
                    uploads.append(_upload(sftp, upload, upload_root, job))
                except Denied as exc:
                    uploads.append({"remote": upload["remote"], "status": "denied", "error": str(exc)})
                    exit_code = 8
                except Exception as exc:  # noqa: BLE001 - opaque remote failure
                    uploads.append(
                        {"remote": upload["remote"], "status": "failed", "error": type(exc).__name__}
                    )
                    exit_code = 8
        finally:
            sftp.close()
        commands: list[dict[str, Any]] = []
        for command in job["commands"]:
            entry: dict[str, Any] = {"argv": command}
            try:
                _, stdout, stderr = client.exec_command(shlex.join(command), timeout=30)
                entry["stdout"], stdout_truncated = _read_capped(stdout)
                entry["stderr"], stderr_truncated = _read_capped(stderr)
                entry["exit_status"] = stdout.channel.recv_exit_status()
                entry["truncated"] = stdout_truncated or stderr_truncated
                entry["status"] = "ok"
            except Exception as exc:  # noqa: BLE001 - opaque remote failure
                entry["status"] = "failed"
                entry["error"] = type(exc).__name__
                exit_code = exit_code or 8
            commands.append(entry)
        payload = {
            "status": "ok" if exit_code == 0 else "remote_error",
            "host": target["host"],
            "port": target["port"],
            "ssh_user": username,
            "profile": job["profile"],
            "commands": commands,
            "uploads": uploads,
        }
        return payload, exit_code
    finally:
        client.close()
