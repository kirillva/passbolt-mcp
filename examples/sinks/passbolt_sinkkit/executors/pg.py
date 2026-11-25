"""PostgreSQL executor: read-only transaction over psycopg. No policy decisions."""

from __future__ import annotations

import base64
import contextlib
import datetime
import decimal
import hashlib
import ipaddress
import json
import uuid
from typing import Any

from passbolt_sinkkit.errors import RemoteFailure, TargetError

MAX_RESULT_BYTES = 1_048_576


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"base64": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, (decimal.Decimal, ipaddress.IPv4Address, ipaddress.IPv6Address, uuid.UUID)):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return str(value)


def _bounded_rows(rows: list[list[Any]], limit: int) -> tuple[list, bool]:
    truncated = len(rows) > limit
    kept: list[list[Any]] = []
    size = 0
    for row in rows[:limit]:
        safe = [_json_safe(value) for value in row]
        size += len(json.dumps(safe, ensure_ascii=False, default=str))
        if kept and size > MAX_RESULT_BYTES:
            truncated = True
            break
        kept.append(safe)
    return kept, truncated


def run(
    target: dict[str, Any],
    username: str,
    password: str,
    job: dict[str, Any],
    *,
    sslmode: str = "prefer",
    sslrootcert: str | None = None,
) -> dict[str, Any]:
    try:
        import psycopg
    except ImportError as exc:
        raise RemoteFailure("psycopg is not installed") from exc
    options = (
        "-c default_transaction_read_only=on "
        f"-c statement_timeout={job['statement_timeout_ms']} "
        "-c lock_timeout=5000 -c idle_in_transaction_session_timeout=20000"
    )
    connect_args: dict[str, Any] = {
        "host": target["host"],
        "port": target["port"],
        "dbname": target["database"],
        "user": username,
        "password": password,
        "connect_timeout": 15,
        "options": options,
        "sslmode": sslmode,
    }
    if sslrootcert:
        connect_args["sslrootcert"] = sslrootcert
    try:
        connection = psycopg.connect(**connect_args)
    except Exception as exc:  # noqa: BLE001 - provider errors stay opaque
        raise TargetError("database connection failed") from exc
    try:
        connection.autocommit = True
        with connection.cursor() as cursor:
            cursor.execute("BEGIN TRANSACTION READ ONLY")
            try:
                cursor.execute(f"SET LOCAL statement_timeout = {int(job['statement_timeout_ms'])}")
                cursor.execute(job["sql"])
                columns = [item.name for item in cursor.description] if cursor.description else []
                fetched = cursor.fetchmany(job["max_rows"] + 1) if cursor.description else []
                raw_rows = [list(row) for row in fetched]
            finally:
                with contextlib.suppress(Exception):
                    cursor.execute("ROLLBACK")
    except Exception as exc:  # noqa: BLE001 - provider errors stay opaque
        raise RemoteFailure("query failed") from exc
    finally:
        connection.close()
    rows, truncated = _bounded_rows(raw_rows, job["max_rows"])
    return {
        "status": "ok",
        "host": target["host"],
        "port": target["port"],
        "database": target["database"],
        "db_user": username,
        "sql_sha256": hashlib.sha256(job["sql"].encode()).hexdigest(),
        "columns": columns,
        "rows": rows,
        "row_count": len(rows),
        "truncated": truncated,
    }
