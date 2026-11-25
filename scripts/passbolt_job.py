"""Create a one-time job file for the pg_ro / ssh_ops sinks.

The job carries no secrets: only SQL or argv/uploads. The reference printed on
stdout is passed to ``passbolt_use_secret(job_ref=...)``; the server hashes the
file into the approval digest and the sink archives it after execution.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shlex
import stat
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "examples" / "sinks"
sys.path.insert(0, str(SOURCES))

from passbolt_sinkkit.guards import ssh as ssh_guard  # noqa: E402
from passbolt_sinkkit.guards.sql import validate_pg_job  # noqa: E402


def _job_dir(value: str | None) -> Path:
    directory = Path(value).resolve() if value else ROOT / "state" / "jobs"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    return directory


def _write(directory: Path, job: dict[str, Any]) -> str:
    reference = uuid.uuid4().hex
    descriptor, raw = tempfile.mkstemp(prefix="job-", suffix=".json", dir=directory)
    temporary = Path(raw)
    try:
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(job, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, directory / f"{reference}.json")
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()
    return reference


def _sql(args: argparse.Namespace) -> str:
    if args.sql_file:
        return Path(args.sql_file).read_text(encoding="utf-8")
    return args.sql or ""


def _pg(args: argparse.Namespace) -> dict[str, Any]:
    job = {
        "version": 1,
        "sink": "pg_ro",
        "sql": _sql(args),
        "max_rows": args.max_rows,
        "statement_timeout_ms": args.timeout_ms,
    }
    validate_pg_job(job)
    return job


def _ssh(args: argparse.Namespace) -> dict[str, Any]:
    commands = [shlex.split(item) for item in args.command]
    uploads = []
    for item in args.upload:
        local, separator, remote = item.partition(":")
        if not separator or not local or not remote:
            raise SystemExit("--upload expects LOCAL:REMOTE")
        uploads.append({"local": local, "remote": remote})
    job = {
        "version": 1,
        "sink": args.sink,
        "profile": args.profile,
        "commands": commands,
        "uploads": uploads,
        "allow_overwrite": args.allow_overwrite,
    }
    if args.sink == "ssh_ops" and not args.profile:
        raise SystemExit("ssh_ops requires --profile")
    if args.sink == "ssh_adhoc" and not args.profile:
        job.pop("profile")
    profiles = ssh_guard.load_profiles(args.profiles) if args.profiles else None
    ssh_guard.validate_ssh_job(job, adhoc=args.sink == "ssh_adhoc", profiles=profiles)
    return job


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="kind", required=True)

    pg = subparsers.add_parser("pg", help="read-only SQL job for pg_ro")
    source = pg.add_mutually_exclusive_group(required=True)
    source.add_argument("--sql-file")
    source.add_argument("--sql")
    pg.add_argument("--max-rows", type=int, default=200)
    pg.add_argument("--timeout-ms", type=int, default=15_000)
    pg.add_argument("--job-dir")

    ssh = subparsers.add_parser("ssh", help="commands/uploads job for ssh_ops")
    ssh.add_argument("--sink", choices=["ssh_ops", "ssh_adhoc"], default="ssh_ops")
    ssh.add_argument("--profile")
    ssh.add_argument("--command", action="append", default=[])
    ssh.add_argument("--upload", action="append", default=[], metavar="LOCAL:REMOTE")
    ssh.add_argument("--allow-overwrite", action="store_true")
    ssh.add_argument("--profiles", help="ssh-profiles.json; enables the full allowlist check")
    ssh.add_argument("--job-dir")

    args = parser.parse_args()
    if args.kind == "pg":
        job = _pg(args)
        directory = _job_dir(args.job_dir)
    else:
        if not args.command and not args.upload:
            raise SystemExit("ssh job needs at least one --command or --upload")
        job = _ssh(args)
        directory = _job_dir(args.job_dir)
    print(_write(directory, job))
    return 0



if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 - CLI boundary, no secrets involved
        print(f"job error: {error}", file=sys.stderr)
        sys.exit(2)
