"""Sink entrypoint: compose envelope -> guard -> executor -> result.

All sinks share this file; the protocol is chosen by the thin entrypoint.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from passbolt_sinkkit.envelope import credentials, page_marker, parse_target
from passbolt_sinkkit.errors import SinkError
from passbolt_sinkkit.executors import pg as pg_executor
from passbolt_sinkkit.executors import ssh as ssh_executor
from passbolt_sinkkit.executors import web as web_executor
from passbolt_sinkkit.guards import ssh as ssh_guard
from passbolt_sinkkit.guards import web as web_guard
from passbolt_sinkkit.guards.sql import validate_pg_job
from passbolt_sinkkit.results import Result

PROTOCOLS = {"web": "login_fill", "pg": "pg_ro", "ssh": "ssh_ops"}
DEFAULT_PORTS = {"web": 443, "pg": 5432, "ssh": 22}
DEFAULT_DATABASES = {"web": None, "pg": "postgres", "ssh": None}


def _parser(protocol: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"passbolt-sink-{protocol}")
    parser.add_argument("--result-dir")
    if protocol == "web":
        parser.add_argument("--web-profiles")
        parser.add_argument("--cdp", default="http://127.0.0.1:9222")
    elif protocol == "pg":
        parser.add_argument("--sslmode", default="require")
        parser.add_argument("--sslrootcert")
        parser.add_argument("--psql")
    elif protocol == "ssh":
        parser.add_argument("--profiles")
        parser.add_argument("--known-hosts", required=True)
        parser.add_argument("--upload-root", required=True)
        parser.add_argument("--adhoc", action="store_true")
    else:
        raise SystemExit(f"unknown protocol: {protocol}")
    return parser


def _values(envelope: dict[str, Any], username: str, password: str) -> dict[str, str | None]:
    totp = envelope.get("totp")
    if totp is not None and not isinstance(totp, str):
        totp = None
    return {"username": username, "password": password, "totp": totp}


def main(protocol: str | None = None, argv: list[str] | None = None) -> int:
    if protocol is None:
        trailing = argv if argv is not None else sys.argv[1:]
        protocol = trailing[0] if trailing else "web"
        if protocol not in PROTOCOLS:
            raise SystemExit(f"unknown protocol: {protocol}")
    args = _parser(protocol).parse_args(argv)
    workdir = Path(sys.argv[0]).resolve().parent
    sink = "ssh_adhoc" if protocol == "ssh" and getattr(args, "adhoc", False) else PROTOCOLS[protocol]
    result = Result(Path(args.result_dir) if args.result_dir else workdir / "results", sink)
    try:
        envelope = json.load(sys.stdin)
        if not isinstance(envelope, dict):
            raise SinkError("envelope must be an object")
        username, password = credentials(envelope)
        target = parse_target(
            envelope,
            default_port=DEFAULT_PORTS[protocol],
            default_database=DEFAULT_DATABASES[protocol],
        )
        result.update(host=target["host"], port=target["port"])
        values = _values(envelope, username, password)
        if protocol == "web":
            marker = page_marker(envelope)
            document = web_guard.load_profiles(args.web_profiles)
            plan = web_guard.build_plan(document, target)
            lock_name = f".browser-{marker}.lock" if marker else ".browser.lock"
            payload = web_executor.run(
                target,
                plan,
                values,
                cdp_url=args.cdp,
                lock_path=workdir / lock_name,
                page=marker,
            )
            result.update(**payload)
            return 0
        if protocol == "pg":
            job = validate_pg_job(envelope.get("job"))
            payload = pg_executor.run(
                target,
                username,
                password,
                job,
                sslmode=args.sslmode,
                sslrootcert=args.sslrootcert,
                psql_binary=args.psql,
            )
            result.update(**payload)
            return 0
        profiles = ssh_guard.load_profiles(args.profiles)
        job = ssh_guard.validate_ssh_job(
            envelope.get("job"), adhoc=bool(args.adhoc), profiles=profiles
        )
        payload, code = ssh_executor.run(
            target,
            username,
            password,
            job,
            known_hosts=args.known_hosts,
            upload_root=Path(args.upload_root),
        )
        result.update(**payload)
        return code
    except SinkError as exc:
        result.update(status=exc.status, error=type(exc).__name__, detail=str(exc)[:300])
        return exc.exit_code
    except Exception as exc:  # noqa: BLE001 - never leak a secret at the CLI boundary
        if os.environ.get("PASSBOLT_SINK_DEBUG") == "1":
            raise
        result.update(status="error", error=type(exc).__name__)
        return 9
    finally:
        result.write()
        # One line for the server: outcome only, never a secret or a full row set.
        printable = {
            key: result.payload[key]
            for key in ("status", "sink", "url", "account", "page", "host", "port", "error", "detail")
            if result.payload.get(key) is not None
        }
        print(json.dumps(printable, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
