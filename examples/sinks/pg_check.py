#!/usr/bin/env python3
"""PostgreSQL credential check over psql: fixed read-only queries, no job.

A diagnostic sink, not a query surface: it answers "does this vault credential
open that database, and which server is it". The report lands in the private
result directory (0600) and one JSON line goes to stdout for the server.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from passbolt_sinkkit.envelope import credentials, parse_target  # noqa: E402
from passbolt_sinkkit.errors import SinkError  # noqa: E402
from passbolt_sinkkit.executors import psql  # noqa: E402

QUERIES = (
    ("version", "SELECT version() AS version"),
    (
        "identity",
        "SELECT current_database() AS database, current_user AS db_user,"
        " inet_server_addr()::text AS addr, inet_server_port() AS port",
    ),
    ("databases", "SELECT count(*) AS databases FROM pg_database"),
    ("recovery", "SELECT pg_is_in_recovery() AS in_recovery"),
)
STATEMENT_TIMEOUT_MS = 10_000


def _report(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode())
    finally:
        os.close(descriptor)


def _utf8_stdout() -> None:
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        # Best effort on odd consoles: the server reads UTF-8.
        with suppress(Exception):
            reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    _utf8_stdout()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-dir", required=True)
    parser.add_argument("--psql")
    parser.add_argument("--sslmode", default="require")
    parser.add_argument("--sslrootcert")
    args = parser.parse_args(argv)

    code = 0
    try:
        envelope = json.load(sys.stdin)
        username, password = credentials(envelope)
        target = parse_target(envelope, default_port=5432, default_database="postgres")
        checks: dict[str, Any] = {}
        psql_version = "unknown"
        for name, sql in QUERIES:
            result = psql.query(
                target,
                username,
                password,
                sql,
                max_rows=20,
                statement_timeout_ms=STATEMENT_TIMEOUT_MS,
                sslmode=args.sslmode,
                sslrootcert=args.sslrootcert,
                psql=args.psql,
                appname="passbolt-mcp-pg_exec",
            )
            psql_version = result["psql_version"]
            checks[name] = {"columns": result["columns"], "rows": result["rows"]}
        payload: dict[str, Any] = {
            "status": "ok",
            "sink": "pg_exec",
            "version": 1,
            "host": target["host"],
            "port": target["port"],
            "database": target["database"],
            "db_user": username,
            "psql_version": psql_version,
            "checks": checks,
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "secret_disclosed": False,
        }
    except SinkError as exc:
        payload = {
            "status": exc.status,
            "sink": "pg_exec",
            "version": 1,
            "error": type(exc).__name__,
            "detail": str(exc)[:300],
            "secret_disclosed": False,
        }
        code = exc.exit_code
    except Exception as exc:  # noqa: BLE001 - never leak an envelope or a secret
        payload = {
            "status": "error",
            "sink": "pg_exec",
            "version": 1,
            "error": type(exc).__name__,
            "secret_disclosed": False,
        }
        code = 9

    _report(Path(args.result_dir) / "pg_exec-last.json", payload)
    printable = {key: value for key, value in payload.items() if key != "checks"}
    print(json.dumps(printable, ensure_ascii=False))
    return code


if __name__ == "__main__":
    sys.exit(main())
