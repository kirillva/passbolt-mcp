"""Read-only SQL guard: one statement, no writes, no dangerous functions."""

from __future__ import annotations

import re

from passbolt_sinkkit.errors import JobError

MAX_SQL_BYTES = 65_536
MAX_ROWS_CEILING = 1_000
DEFAULT_ROWS = 200
DEFAULT_TIMEOUT_MS = 15_000

_DENY_KEYWORDS = frozenset(
    {
        "insert",
        "update",
        "delete",
        "merge",
        "create",
        "alter",
        "drop",
        "truncate",
        "grant",
        "revoke",
        "copy",
        "do",
        "call",
        "execute",
        "set",
        "reset",
        "begin",
        "start",
        "commit",
        "rollback",
        "savepoint",
        "release",
        "discard",
        "listen",
        "notify",
        "unlisten",
        "vacuum",
        "analyze",
        "reindex",
        "cluster",
        "refresh",
        "import",
        "security",
        "lock",
        "into",
        "outfile",
        "load",
        "handler",
        "prepare",
        "deallocate",
        "declare",
        "fetch",
        "move",
        "close",
        "nextval",
        "setval",
        "currval",
    }
)
_DENY_FUNCTIONS = frozenset(
    {
        "pg_read_file",
        "pg_read_binary_file",
        "pg_ls_dir",
        "pg_ls_waldir",
        "pg_ls_logdir",
        "pg_ls_tmpdir",
        "lo_export",
        "lo_import",
        "lo_unlink",
        "lo_from_bytea",
        "dblink",
        "dblink_exec",
        "dblink_connect",
        "pg_terminate_backend",
        "pg_cancel_backend",
        "pg_reload_conf",
        "pg_rotate_logfile",
        "pg_switch_wal",
        "pg_create_restore_point",
        "pg_promote",
        "pg_backup_start",
        "pg_backup_stop",
        "pg_stat_reset",
        "pg_stat_reset_shared",
        "pg_logical_emit_message",
        "set_config",
        "query_to_xml",
        "query_to_xmlschema",
        "database_to_xml",
        "table_to_xml",
        "pg_import_system_collations",
        "pg_export_snapshot",
    }
)


def _strip_literals(sql: str) -> str:
    """Blank out comments and literals, keeping identifiers and keywords."""
    out: list[str] = []
    index = 0
    length = len(sql)
    while index < length:
        char = sql[index]
        if char == "'":
            index += 1
            while index < length:
                if sql[index] == "'":
                    if index + 1 < length and sql[index + 1] == "'":
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            out.append(" ")
        elif char == "-" and sql.startswith("--", index):
            line = sql.find("\n", index)
            index = length if line < 0 else line + 1
            out.append(" ")
        elif char == "/" and sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            index = length if end < 0 else end + 2
            out.append(" ")
        elif char == '"':
            index += 1
            buffer: list[str] = []
            while index < length:
                if sql[index] == '"':
                    if index + 1 < length and sql[index + 1] == '"':
                        buffer.append('"')
                        index += 2
                        continue
                    index += 1
                    break
                buffer.append(sql[index])
                index += 1
            out.append(" " + "".join(buffer).lower() + " ")
        else:
            out.append(char)
            index += 1
    return "".join(out)


def validate_readonly_sql(sql: str) -> None:
    """Reject anything that is not one read-only statement (fail closed).

    PostgreSQL's READ ONLY transaction does not stop every side effect for a
    superuser (file reads, COPY TO PROGRAM, dblink...). This lexical guard plus
    the read-only transaction is the minimum defence until a dedicated
    read-only role exists.
    """
    if not isinstance(sql, str) or not sql.strip():
        raise JobError("sql is required")
    if len(sql.encode("utf-8")) > MAX_SQL_BYTES:
        raise JobError("sql is too large")
    body = _strip_literals(sql).strip()
    if "\\" in body:
        # psql meta-commands (\!, \o, \copy) are shell and file access, not SQL.
        raise JobError("psql meta-commands are not allowed")
    if body.endswith(";"):
        body = body[:-1].rstrip()
    if ";" in body:
        raise JobError("multiple statements are not allowed")
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_$]*", body.lower())
    if not tokens:
        raise JobError("sql is empty")
    if tokens[0] not in {"select", "with", "values", "table"}:
        raise JobError("only SELECT/WITH/UNION/TABLE/VALUES queries are allowed")
    if tokens[0] == "with" and "select" not in tokens:
        raise JobError("WITH must contain a SELECT")
    for token in tokens:
        if token in _DENY_KEYWORDS:
            raise JobError(f"forbidden keyword: {token}")
        if token in _DENY_FUNCTIONS:
            raise JobError(f"forbidden function: {token}")


def wrap_readonly_query(sql: str, max_rows: int) -> str:
    """Bound a validated statement and ask for one JSON object per row.

    `row_to_json` keeps PostgreSQL types (numbers stay numbers, NULL stays null) and
    escapes newlines, so every line is one complete row. `-c` has no fetch size, so the
    outer LIMIT is the only row bound psql can apply.
    """
    body = sql.strip().rstrip(";").strip()
    return f'SELECT row_to_json("_pb")::text FROM ({body}) AS "_pb" LIMIT {int(max_rows) + 1}'


def validate_pg_job(job: object) -> dict:
    if not isinstance(job, dict):
        raise JobError("job must be an object")
    allowed = {"version", "sink", "sql", "max_rows", "statement_timeout_ms"}
    if set(job) - allowed:
        raise JobError("job contains unsupported fields")
    if job.get("version") != 1:
        raise JobError("job version must be 1")
    if job.get("sink") != "pg_ro":
        raise JobError("job belongs to another sink")
    sql = job.get("sql")
    validate_readonly_sql(sql)
    max_rows = job.get("max_rows", DEFAULT_ROWS)
    if isinstance(max_rows, bool) or not isinstance(max_rows, int) or not 1 <= max_rows <= MAX_ROWS_CEILING:
        raise JobError("max_rows is out of range")
    timeout = job.get("statement_timeout_ms", DEFAULT_TIMEOUT_MS)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 100 <= timeout <= 60_000:
        raise JobError("statement_timeout_ms is out of range")
    return {"sql": sql, "max_rows": max_rows, "statement_timeout_ms": timeout}
