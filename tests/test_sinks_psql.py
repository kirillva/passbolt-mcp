from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SINKS = ROOT / "examples" / "sinks"
sys.path.insert(0, str(SINKS))

from passbolt_sinkkit.errors import JobError, RemoteFailure, SinkError, TargetError  # noqa: E402
from passbolt_sinkkit.executors import psql  # noqa: E402
from passbolt_sinkkit.guards.sql import validate_readonly_sql, wrap_readonly_query  # noqa: E402

TARGET = {"host": "db.example", "port": 5432, "path": "/", "database": "postgres", "scheme": "postgresql"}
PASSWORD = "s3cr:et\\pw"


def fake_psql(
    tmp_path: Path,
    *,
    rows: list[dict[str, Any]] | None = None,
    code: int = 0,
    huge: bool = False,
    stderr: str = "",
) -> tuple[Path, Path]:
    """A psql stand-in that records its argv/env/passfile and prints canned rows."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    record = tmp_path / "calls.jsonl"
    binary = tmp_path / "psql"
    payload = rows or []
    script = f'''#!{sys.executable}
import json, os, stat, sys
record = {str(record)!r}
argv = sys.argv[1:]
if "--version" in argv:
    print("psql (PostgreSQL) 18.6 (fake)")
    sys.exit(0)
entry = {{"argv": argv}}
for key in ("PGPASSFILE", "PGOPTIONS", "PGSSLMODE", "PGPASSWORD", "PGCONNECT_TIMEOUT", "PGAPPNAME"):
    entry[key] = os.environ.get(key)
path = os.environ.get("PGPASSFILE")
if path:
    entry["passfile_mode"] = stat.S_IMODE(os.stat(path).st_mode)
    entry["passfile"] = open(path, encoding="utf-8").read()
    entry["passfile_path"] = path
with open(record, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(entry) + "\\n")
if {code!r}:
    sys.stderr.write({stderr!r})
    sys.exit({code})
if {huge!r}:
    sys.stdout.write('{{"blob":"' + "x" * (2 * 1024 * 1024) + '"}}\\n')
else:
    for row in {payload!r}:
        sys.stdout.write(json.dumps(row) + "\\n")
'''
    binary.write_text(script, encoding="utf-8")
    binary.chmod(0o700)
    return binary, record


def calls(record: Path) -> list[dict[str, Any]]:
    entries = [json.loads(line) for line in record.read_text(encoding="utf-8").splitlines()]
    return [entry for entry in entries if "-c" in entry["argv"]]


def test_query_keeps_the_password_off_argv_and_cleans_up(tmp_path: Path) -> None:
    binary, record = fake_psql(tmp_path, rows=[{"id": 1, "name": "one"}, {"id": 2, "name": None}])

    result = psql.query(
        TARGET,
        "postgres",
        PASSWORD,
        "select id, name from t",
        max_rows=10,
        statement_timeout_ms=5000,
        sslmode="require",
        psql=str(binary),
    )

    assert result["columns"] == ["id", "name"]
    assert result["rows"] == [[1, "one"], [2, None]]
    assert result["row_count"] == 2 and result["truncated"] is False
    assert result["format"] == "json-rows" and "18.6" in result["psql_version"]

    [entry] = calls(record)
    argv = entry["argv"]
    assert PASSWORD not in " ".join(argv)
    for flag in ("-X", "-w", "-q", "-v", "ON_ERROR_STOP=1", "-A", "-t"):
        assert flag in argv
    assert argv[argv.index("-h") + 1] == "db.example"
    assert argv[argv.index("-p") + 1] == "5432"
    assert argv[argv.index("-U") + 1] == "postgres"
    assert argv[argv.index("-d") + 1] == "postgres"
    wrapped = argv[argv.index("-c") + 1]
    assert wrapped.startswith('SELECT row_to_json("_pb")::text FROM (select id, name from t)')
    assert wrapped.endswith("LIMIT 11")

    assert entry["PGPASSWORD"] is None
    assert "default_transaction_read_only=on" in entry["PGOPTIONS"]
    assert "statement_timeout=5000" in entry["PGOPTIONS"]
    assert entry["PGSSLMODE"] == "require"
    assert entry["PGAPPNAME"] == "passbolt-mcp-pg_ro"

    # One line, 0600, this connection only, and gone after the call.
    assert entry["passfile_mode"] == 0o600
    assert entry["passfile"].strip() == "db.example:5432:postgres:postgres:s3cr\\:et\\\\pw"
    assert not Path(entry["passfile_path"]).exists()
    assert not Path(entry["passfile_path"]).parent.exists()


def run_query(binary: Path, sql: str = "select 1", *, max_rows: int = 10) -> dict[str, Any]:
    return psql.query(
        TARGET,
        "postgres",
        PASSWORD,
        sql,
        max_rows=max_rows,
        statement_timeout_ms=1000,
        psql=str(binary),
    )


def test_query_maps_psql_exit_codes(tmp_path: Path) -> None:
    unreachable, _ = fake_psql(tmp_path / "connect", code=2)
    with pytest.raises(TargetError):
        run_query(unreachable)

    failing, _ = fake_psql(tmp_path / "query", code=3)
    with pytest.raises(RemoteFailure):
        run_query(failing)

    broken, _ = fake_psql(tmp_path / "broken", code=1)
    with pytest.raises(SinkError):
        run_query(broken)

    wrapper, _ = fake_psql(
        tmp_path / "wrapper",
        code=1,
        stderr="Error: You must install at least one postgresql-client-<version> package\n",
    )
    with pytest.raises(RemoteFailure, match="versioned client"):
        run_query(wrapper)


def test_query_bounds_rows_and_bytes(tmp_path: Path) -> None:
    binary, _ = fake_psql(tmp_path / "rows", rows=[{"n": 1}, {"n": 2}, {"n": 3}])
    result = run_query(binary, "select n", max_rows=2)
    assert result["row_count"] == 2 and result["truncated"] is True

    huge_binary, _ = fake_psql(tmp_path / "huge", huge=True)
    huge = run_query(huge_binary, "select n", max_rows=2)
    assert huge["truncated"] is True and huge["row_count"] <= 2


def test_psql_path_refuses_unsafe_binaries(tmp_path: Path) -> None:
    not_executable = tmp_path / "psql"
    not_executable.write_text("#!/bin/sh\n", encoding="utf-8")
    not_executable.chmod(0o600)
    with pytest.raises(RemoteFailure):
        psql.psql_path(str(not_executable))

    world_writable = tmp_path / "psql-world"
    world_writable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    world_writable.chmod(0o707)
    with pytest.raises(RemoteFailure):
        psql.psql_path(str(world_writable))

    with pytest.raises(RemoteFailure):
        psql.psql_path(str(tmp_path / "missing"))


def test_psql_path_unwraps_the_distribution_wrapper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    version_dir = tmp_path / "postgresql" / "18" / "bin"
    version_dir.mkdir(parents=True)
    real = version_dir / "psql"
    real.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    real.chmod(0o755)

    wrapper = tmp_path / "pg_wrapper"
    wrapper.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    wrapper.chmod(0o755)
    link = tmp_path / "psql"
    link.symlink_to(wrapper)

    monkeypatch.setattr(psql, "_versioned_psql", lambda: real)
    assert psql.psql_path(str(link)) == str(real.resolve())

    monkeypatch.setattr(psql, "_versioned_psql", lambda: None)
    with pytest.raises(RemoteFailure, match="versioned client"):
        psql.psql_path(str(link))


def test_guard_refuses_psql_meta_commands_and_wraps_for_bounded_json() -> None:
    for sql in ("select 1 \\! id", "select 1; select 2", "copy (select 1) to program 'true'"):
        with pytest.raises(JobError):
            validate_readonly_sql(sql)

    assert wrap_readonly_query("select 1;", 5) == (
        'SELECT row_to_json("_pb")::text FROM (select 1) AS "_pb" LIMIT 6'
    )
    # The wrapper has to stay valid for every shape the guard allows.
    for body in ("select 1", "with x as (select 1) select * from x", "values (1)", "table pg_class"):
        wrapped = wrap_readonly_query(body, 10)
        assert wrapped.startswith('SELECT row_to_json("_pb")::text FROM (')
        assert wrapped.endswith("LIMIT 11")
