"""PostgreSQL executor: one validated read-only statement through psql.

No policy decisions live here, and no secret reaches a command line: the password
travels in a temporary passfile that the shared psql helper removes afterwards.
"""

from __future__ import annotations

import hashlib
from typing import Any

from passbolt_sinkkit.executors import psql


def run(
    target: dict[str, Any],
    username: str,
    password: str,
    job: dict[str, Any],
    *,
    sslmode: str = "require",
    sslrootcert: str | None = None,
    psql_binary: str | None = None,
) -> dict[str, Any]:
    result = psql.query(
        target,
        username,
        password,
        job["sql"],
        max_rows=job["max_rows"],
        statement_timeout_ms=job["statement_timeout_ms"],
        sslmode=sslmode,
        sslrootcert=sslrootcert,
        psql=psql_binary,
        appname="passbolt-mcp-pg_ro",
    )
    return {
        "status": "ok",
        "host": target["host"],
        "port": target["port"],
        "database": target["database"],
        "db_user": username,
        "sql_sha256": hashlib.sha256(job["sql"].encode()).hexdigest(),
        **result,
    }
