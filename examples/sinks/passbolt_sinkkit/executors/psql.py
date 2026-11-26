"""psql plumbing shared by the PostgreSQL sinks: trusted input, no policy decisions.

The password never appears on a command line: psql reads it from a temporary
`PGPASSFILE` (0600) inside a private directory that is removed afterwards, and the
child environment is built from scratch so an inherited `PGPASSWORD` cannot leak.
The server-side statement is read-only by `PGOPTIONS`, and the SQL itself was
already validated by the guard — psql only executes what the guard accepted.
"""

from __future__ import annotations

import csv
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from passbolt_sinkkit.errors import RemoteFailure, SinkError, SinkTimeout, TargetError
from passbolt_sinkkit.guards.sql import wrap_readonly_query

MAX_RESULT_BYTES = 1_048_576
MAX_STDERR_BYTES = 4_096
CONNECT_TIMEOUT_SECONDS = 15
CLIENT_GRACE_SECONDS = 10


def _executable(path: Path) -> Path:
    """Resolve a binary the way the distribution ships it (psql is often a symlink)."""
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise RemoteFailure("psql is not installed") from exc
    try:
        info = resolved.stat()
    except OSError as exc:
        raise RemoteFailure("psql is not installed") from exc
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        raise RemoteFailure("psql is not executable")
    if info.st_mode & 0o002 or resolved.parent.stat().st_mode & 0o002:
        raise RemoteFailure("psql lives in a world-writable location")
    return resolved


def psql_path(value: str | None = None) -> str:
    """Configured psql, else PATH lookup. Never returns a non-executable path."""
    candidate = value or os.environ.get("PASSBOLT_PSQL") or shutil.which("psql")
    if not candidate:
        raise RemoteFailure("psql is not installed")
    path = Path(candidate).expanduser()
    if not path.is_absolute():
        found = shutil.which(str(path))
        if not found:
            raise RemoteFailure("psql is not installed")
        path = Path(found)
    return str(_executable(path))


def _version(binary: str) -> str:
    try:
        output = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return output[:120] or "unknown"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace(":", "\\:")


def _passfile(directory: Path, target: dict[str, Any], username: str, password: str) -> Path:
    """One line for this connection only; psql ignores files that are not 0600."""
    database = str(target.get("database") or "*")
    line = ":".join(
        (
            _escape(str(target["host"])),
            str(int(target["port"])),
            _escape(database),
            _escape(username),
            _escape(password),
        )
    )
    path = directory / "pgpass"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, (line + "\n").encode("utf-8"))
    finally:
        os.close(descriptor)
    return path


def _environment(
    *,
    passfile: Path,
    statement_timeout_ms: int,
    sslmode: str,
    sslrootcert: str | None,
    appname: str,
) -> dict[str, str]:
    # A fresh dict: PGPASSWORD, PGOPTIONS or PGHOST from the caller never reach psql.
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PGPASSFILE": str(passfile),
        "PGCONNECT_TIMEOUT": str(CONNECT_TIMEOUT_SECONDS),
        "PGAPPNAME": appname,
        "PGSSLMODE": sslmode,
        "PGCLIENTENCODING": "UTF8",
        "PGTZ": "UTC",
        "PGDATESTYLE": "ISO",
        "PGOPTIONS": (
            "-c default_transaction_read_only=on "
            f"-c statement_timeout={int(statement_timeout_ms)} "
            "-c lock_timeout=5000 -c idle_in_transaction_session_timeout=20000"
        ),
    }
    if sslrootcert:
        env["PGSSLROOTCERT"] = sslrootcert
    return env


def _run(
    binary: str,
    target: dict[str, Any],
    username: str,
    sql: str,
    env: dict[str, str],
    *,
    timeout_seconds: float,
) -> tuple[int, bytes, bool]:
    """Run one psql statement, bounding both the wall clock and the output bytes."""
    argv = [
        binary,
        "-X",  # never read ~/.psqlrc: a local file must not add meta-commands
        "-q",
        "-w",  # never prompt: a missing passfile is an error, not a hang
        "-v",
        "ON_ERROR_STOP=1",
        "-A",
        "-t",
        "-h",
        str(target["host"]),
        "-p",
        str(int(target["port"])),
        "-U",
        username,
        "-d",
        str(target.get("database") or "postgres"),
        "-c",
        sql,
    ]
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert process.stdout is not None and process.stderr is not None
    deadline = time.monotonic() + timeout_seconds
    chunks: list[bytes] = []
    size = 0
    capped = False
    try:
        while True:
            chunk = process.stdout.read(65_536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_RESULT_BYTES:
                capped = True
                process.kill()
                break
            chunks.append(chunk)
            if time.monotonic() > deadline:
                process.kill()
                raise SinkTimeout("psql statement exceeded its deadline")
        process.stderr.read(MAX_STDERR_BYTES)  # drained, never logged or returned
        code = process.wait(timeout=CLIENT_GRACE_SECONDS)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        raise SinkTimeout("psql did not exit") from exc
    return code, b"".join(chunks), capped


def _columns(binary: str, target: dict[str, Any], username: str, sql: str, env: dict[str, str]) -> list[str]:
    """Header of the wrapped query without fetching rows (cheap plan-only probe)."""
    probe = f'SELECT * FROM ({sql.rstrip().rstrip(";")}) AS "_pb" LIMIT 0'
    argv = [
        binary, "-X", "-q", "-w", "-v", "ON_ERROR_STOP=1", "--csv",
        "-h", str(target["host"]), "-p", str(int(target["port"])),
        "-U", username, "-d", str(target.get("database") or "postgres"),
        "-c", probe,
    ]
    try:
        output = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=env,
            timeout=CONNECT_TIMEOUT_SECONDS + 5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    first = output.stdout[:65_536].decode("utf-8", "replace").splitlines()[:1]
    if not first or output.returncode != 0:
        return []
    try:
        header = next(csv.reader(first), [])
    except csv.Error:
        return []
    return [str(name)[:128] for name in header]


def query(
    target: dict[str, Any],
    username: str,
    password: str,
    sql: str,
    *,
    max_rows: int,
    statement_timeout_ms: int,
    sslmode: str = "require",
    sslrootcert: str | None = None,
    psql: str | None = None,
    appname: str = "passbolt-mcp-pg_ro",
) -> dict[str, Any]:
    """Run one validated read-only statement through psql and return bounded rows."""
    binary = psql_path(psql)
    version = _version(binary)
    wrapped = wrap_readonly_query(sql, max_rows)
    timeout_seconds = CONNECT_TIMEOUT_SECONDS + statement_timeout_ms / 1000 + CLIENT_GRACE_SECONDS
    directory = Path(tempfile.mkdtemp(prefix="passbolt-pg-"))
    os.chmod(directory, 0o700)
    try:
        passfile = _passfile(directory, target, username, password)
        env = _environment(
            passfile=passfile,
            statement_timeout_ms=statement_timeout_ms,
            sslmode=sslmode,
            sslrootcert=sslrootcert,
            appname=appname,
        )
        code, stdout, capped = _run(
            binary, target, username, wrapped, env, timeout_seconds=timeout_seconds
        )
        if not capped:
            if code == 2:
                raise TargetError("database connection failed")
            if code == 3:
                raise RemoteFailure("query failed")
            if code != 0:
                raise SinkError("psql invocation failed")

        text = stdout.decode("utf-8", "replace")
        lines = text.splitlines()
        if capped and text and not text.endswith("\n"):
            lines = lines[:-1]  # the process was killed mid-line; keep complete rows only
        rows: list[dict[str, Any]] = []
        truncated = capped
        for line in lines:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError as exc:
                raise RemoteFailure("psql returned an unreadable row") from exc
            if isinstance(row, dict):
                rows.append(row)
        if len(rows) > max_rows:
            rows = rows[:max_rows]
            truncated = True
        columns = list(rows[0]) if rows else _columns(binary, target, username, sql, env)
    finally:
        shutil.rmtree(directory, ignore_errors=True)

    return {
        "columns": columns,
        "rows": [[row.get(name) for name in columns] for row in rows],
        "row_count": len(rows),
        "truncated": truncated,
        "psql_version": version,
        "format": "json-rows",
    }
