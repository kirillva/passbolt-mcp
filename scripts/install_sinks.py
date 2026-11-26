"""Deploy the example sinks and pin their hashes in the operator sink registry.

The canonical sources live in ``examples/sinks/``. This installer copies them to
the private sink directory (0700), rewrites the shebang to the interpreter that
has the sink's dependencies, computes SHA-256 and updates ``sinks.json``
atomically. It never executes a sink and never touches policies.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "examples" / "sinks"


def _defaults(
    dest: Path,
    state: Path,
    sslmode: str | None,
    sslrootcert: str | None,
    psql: str | None = None,
) -> dict[str, tuple[str, dict[str, Any]]]:
    results = dest / "results"
    pg_command = [str(dest / "pg_query.py"), "--result-dir", str(results)]
    check_command = [str(dest / "pg_check.py"), "--result-dir", str(results)]
    for command in (pg_command, check_command):
        if sslmode:
            command += ["--sslmode", sslmode]
        if sslrootcert:
            command += ["--sslrootcert", sslrootcert]
        if psql:
            command += ["--psql", psql]
    return {
        "login_fill": (
            "login_fill.py",
            {
                "kind": "secure_fill",
                "timeout_seconds": 90,
                "default_port": 443,
                "command": [
                    str(dest / "login_fill.py"),
                    "--web-profiles",
                    str(dest / "web-profiles.json"),
                ],
            },
        ),
        "pg_ro": (
            "pg_query.py",
            {
                "kind": "secure_fill",
                "timeout_seconds": 60,
                "default_port": 5432,
                "default_database": "postgres",
                "uri_schemes": ["postgresql", "postgres"],
                "allow_bare_host": True,
                "requires_job": True,
                "require_approval": "never",
                "job_dir": str(state / "jobs"),
                "max_job_bytes": 65_536,
                **({"sslmode": sslmode} if sslmode else {}),
                **({"sslrootcert": sslrootcert} if sslrootcert else {}),
                "command": pg_command,
            },
        ),
        "pg_exec": (
            "pg_check.py",
            {
                "kind": "secure_fill",
                "timeout_seconds": 90,
                "default_port": 5432,
                "default_database": "postgres",
                "uri_schemes": ["postgresql", "postgres"],
                "allow_bare_host": True,
                "requires_job": False,
                "require_approval": "never",
                **({"sslmode": sslmode} if sslmode else {}),
                **({"sslrootcert": sslrootcert} if sslrootcert else {}),
                "command": check_command,
            },
        ),
        "ssh_ops": (
            "ssh_ops.py",
            {
                "kind": "secure_fill",
                "timeout_seconds": 120,
                "default_port": 22,
                "uri_schemes": ["ssh"],
                "allow_bare_host": True,
                "requires_job": True,
                "require_approval": "never",
                "job_dir": str(state / "jobs"),
                "max_job_bytes": 65_536,
                "command": [
                    str(dest / "ssh_ops.py"),
                    "--profiles",
                    str(dest / "ssh-profiles.json"),
                    "--known-hosts",
                    str(dest / "known_hosts"),
                    "--upload-root",
                    str(state / "upload"),
                    "--result-dir",
                    str(results),
                ],
            },
        ),
        "ssh_adhoc": (
            "ssh_ops.py",
            {
                "kind": "secure_fill",
                "timeout_seconds": 120,
                "default_port": 22,
                "uri_schemes": ["ssh"],
                "allow_bare_host": True,
                "requires_job": True,
                "require_approval": "always",
                "job_dir": str(state / "jobs"),
                "max_job_bytes": 65_536,
                "command": [
                    str(dest / "ssh_ops.py"),
                    "--profiles",
                    str(dest / "ssh-profiles.json"),
                    "--known-hosts",
                    str(dest / "known_hosts"),
                    "--upload-root",
                    str(state / "upload"),
                    "--result-dir",
                    str(results),
                    "--adhoc",
                ],
            },
        ),
    }


def _python_map(values: list[str], fallback: Path) -> dict[str, Path]:
    mapping = {
        "login_fill": fallback,
        "pg_ro": fallback,
        "pg_exec": fallback,
        "ssh_ops": fallback,
        "ssh_adhoc": fallback,
    }
    for item in values:
        name, _, path = item.partition("=")
        if name not in mapping or not path:
            raise SystemExit(f"--python expects NAME=PATH for {', '.join(mapping)}")
        mapping[name] = Path(path)
    return mapping


def _install_script(source: Path, target: Path, interpreter: Path) -> str:
    payload = source.read_bytes()
    if not payload.startswith(b"#!"):
        raise SystemExit(f"{source.name} has no shebang")
    first, _, rest = payload.partition(b"\n")
    shebang = f"#!{interpreter}".encode()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.write_bytes(shebang + b"\n" + rest)
    target.chmod(0o700)
    info = target.lstat()
    if target.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"{target} is not a regular file")
    return hashlib.sha256(target.read_bytes()).hexdigest()


def _bundle_digest(directory: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(
        path
        for path in directory.rglob("*.py")
        if "__pycache__" not in path.relative_to(directory).parts
    )
    if not files:
        raise SystemExit("sink bundle is empty")
    for path in files:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise SystemExit("sink bundle is unsafe")
        digest.update(path.relative_to(directory).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _install_bundle(dest: Path) -> str:
    source = SOURCE / "passbolt_sinkkit"
    if not source.is_dir():
        raise SystemExit(f"sink package is missing: {source}")
    target = dest / "passbolt_sinkkit"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for path in sorted(target.rglob("*")):
        path.chmod(0o700 if path.is_dir() else 0o600)
    target.chmod(0o700)
    return _bundle_digest(target)


def _write_atomic(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, raw = tempfile.mkstemp(prefix="sinks-", suffix=".json", dir=path.parent)
    temporary = Path(raw)
    try:
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", default=str(ROOT / "secrets" / "sinks"))
    parser.add_argument("--config", default=str(ROOT / "secrets" / "sinks.json"))
    parser.add_argument("--state", default=str(ROOT / "state"))
    parser.add_argument(
        "--python",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="interpreter for login_fill, pg_ro, ssh_ops, ssh_adhoc",
    )
    parser.add_argument("--only", default="", help="comma-separated sink names")
    parser.add_argument("--pg-sslmode", default="require", help="libpq sslmode, e.g. require or verify-full")
    parser.add_argument("--pg-sslrootcert", default=None)
    parser.add_argument("--psql", default=None, help="absolute path to psql (default: PATH lookup)")
    args = parser.parse_args()

    dest = Path(args.dest).resolve()
    state = Path(args.state).resolve()
    config_path = Path(args.config).resolve()
    for directory in (dest, dest / "results", state / "jobs", state / "upload"):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    interpreters = _python_map(args.python, Path(sys.executable))
    only = {item.strip() for item in args.only.split(",") if item.strip()}
    definitions = _defaults(dest, state, args.pg_sslmode, args.pg_sslrootcert, args.psql)
    if only - set(definitions):
        raise SystemExit(f"unknown sink in --only: {', '.join(sorted(only - set(definitions)))}")

    try:
        document = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        document = {"version": 3, "sinks": {}, "policies": {}}
    if not isinstance(document, dict) or not isinstance(document.get("sinks"), dict):
        raise SystemExit("sink registry is invalid")
    document["version"] = 3
    sinks = document["sinks"]

    bundle = _install_bundle(dest)
    installed = []
    for name, (filename, definition) in definitions.items():
        if only and name not in only:
            continue
        digest = _install_script(SOURCE / filename, dest / filename, interpreters[name])
        existing = sinks.get(name) if isinstance(sinks.get(name), dict) else {}
        merged = {
            **existing,
            **definition,
            "executable_sha256": digest,
            "bundle_sha256": bundle,
        }
        sinks[name] = merged
        installed.append(name)

    if not (dest / "ssh-profiles.json").exists():
        print(f"warning: create {dest / 'ssh-profiles.json'} (0600) before using ssh_ops", file=sys.stderr)
    if not (dest / "known_hosts").exists():
        print(f"warning: create {dest / 'known_hosts'} before using ssh_ops", file=sys.stderr)
    _write_atomic(config_path, document)
    print("installed: " + ", ".join(installed))
    print(f"registry: {config_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
