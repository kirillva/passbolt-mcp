from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from zai_passbolt.adapter import PassboltSinkDispatcher, _sink_target
from zai_passbolt.errors import safe_provider_error
from zai_passbolt.transport import ProviderConfigurationError, ProviderError

ROOT = Path(__file__).resolve().parents[1]
SINKS = ROOT / "examples" / "sinks"
sys.path.insert(0, str(SINKS))

from passbolt_sinkkit.envelope import parse_target  # noqa: E402
from passbolt_sinkkit.errors import Denied, InputError, JobError, SinkError  # noqa: E402
from passbolt_sinkkit.guards import ssh as ssh_guard  # noqa: E402
from passbolt_sinkkit.guards import web as web_guard  # noqa: E402
from passbolt_sinkkit.guards.sql import validate_pg_job, validate_readonly_sql  # noqa: E402


def test_sink_target_defaults_and_explicit_port() -> None:
    assert _sink_target("https://db.example", default_port=5432, default_database="postgres") == {
        "uri": "https://db.example",
        "scheme": "https",
        "host": "db.example",
        "port": 5432,
        "path": "/",
        "database": "postgres",
    }
    explicit = _sink_target("https://db.example:443/app", default_port=5432, default_database="postgres")
    assert explicit["port"] == 443 and explicit["database"] == "app"
    web = _sink_target("https://portal.example/login", default_port=443, default_database=None)
    assert web["port"] == 443 and web["path"] == "/login" and web["database"] is None


def test_plain_http_record_needs_the_operator_opt_in() -> None:
    """A lab site on plain HTTP is usable, but only when the operator said so."""
    with pytest.raises(ProviderConfigurationError, match="plain HTTP"):
        _sink_target("http://lab.example/app", default_port=443, default_database=None)

    target = _sink_target(
        "http://lab.example/app",
        default_port=443,
        default_database=None,
        allow_plain_http=True,
    )
    assert target["scheme"] == "http" and target["port"] == 80 and target["path"] == "/app"
    pinned = _sink_target(
        "http://lab.example:8080/app",
        default_port=443,
        default_database=None,
        allow_plain_http=True,
    )
    assert pinned["port"] == 8080


def test_allows_plain_http_flag_wins_over_the_global_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PASSBOLT_ALLOW_INSECURE_HTTP", raising=False)
    assert PassboltSinkDispatcher.allows_plain_http({}) is False
    monkeypatch.setenv("PASSBOLT_ALLOW_INSECURE_HTTP", "1")
    assert PassboltSinkDispatcher.allows_plain_http({}) is True
    # One lab sink may opt in while another stays HTTPS-only.
    assert PassboltSinkDispatcher.allows_plain_http({"allow_insecure_uri": False}) is False
    assert PassboltSinkDispatcher.allows_plain_http({"allow_insecure_uri": True}) is True
    with pytest.raises(ProviderError):
        PassboltSinkDispatcher.allows_plain_http({"allow_insecure_uri": "yes"})


def test_configuration_error_carries_an_actionable_hint() -> None:
    """Only our own configuration text reaches the caller; provider errors stay opaque."""
    error = safe_provider_error(
        "passbolt",
        ProviderConfigurationError(
            'Passbolt resource URI uses plain HTTP; store HTTPS or set "allow_insecure_uri": true'
        ),
    )
    assert error.error_code == "provider_configuration_invalid"
    assert "allow_insecure_uri" in error.envelope["hint"]

    opaque = safe_provider_error("passbolt", ProviderError("vault said: secret-token"))
    assert "hint" not in opaque.envelope
    assert "secret-token" not in str(opaque)


@pytest.mark.parametrize("uri", [None, "", "https://", "https://db.example?x=1", "https://db.example#f"])
def test_sink_target_rejects_unusable_uri(uri: str | None) -> None:
    with pytest.raises(ProviderError):
        _sink_target(uri, default_port=5432, default_database="postgres")


def test_envelope_parses_target_and_falls_back_to_url() -> None:
    target = parse_target(
        {"target": {"host": "DB.Example", "port": 5432, "path": "/app", "database": "app"}},
        default_port=5432,
        default_database="postgres",
    )
    assert target["host"] == "db.example" and target["database"] == "app"
    fallback = parse_target(
        {"target_url": "https://db.example:443/app"},
        default_port=5432,
        default_database="postgres",
    )
    assert fallback["port"] == 443 and fallback["database"] == "app"
    # A web record on plain HTTP keeps its own port instead of the sink default.
    lab = parse_target({"target_url": "http://lab.example/app"}, default_port=443, default_database=None)
    assert lab["host"] == "lab.example" and lab["port"] == 80
    with pytest.raises(SinkError):
        parse_target(
            {"target_url": "http://user:pass@lab.example/app"}, default_port=443, default_database=None
        )


def _registry(path: Path, sinks: dict[str, Any]) -> None:
    path.write_text(json.dumps({"version": 3, "sinks": sinks}), encoding="utf-8")
    path.chmod(0o600)


def _job_sink(tmp_path: Path, *, max_bytes: int = 4096) -> tuple[Path, Path]:
    jobs = tmp_path / "jobs"
    jobs.mkdir(mode=0o700)
    registry = tmp_path / "sinks.json"
    _registry(
        registry,
        {
            "pg_ro": {
                "kind": "secure_fill",
                "command": [sys.executable, "-c", "pass"],
                "executable_sha256": "0" * 64,
                "requires_job": True,
                "job_dir": str(jobs),
                "max_job_bytes": max_bytes,
            }
        },
    )
    return registry, jobs


def test_job_is_loaded_and_archived(tmp_path: Path) -> None:
    registry, jobs = _job_sink(tmp_path)
    path = jobs / "abc123.json"
    path.write_text(json.dumps({"version": 1, "sink": "pg_ro", "sql": "select 1"}), encoding="utf-8")
    path.chmod(0o600)
    dispatcher = PassboltSinkDispatcher(registry)
    payload, digest = dispatcher.load_job("pg_ro", "abc123")
    assert payload["sql"] == "select 1" and len(digest) == 64
    dispatcher.archive_job("pg_ro", "abc123")
    assert not path.exists()
    assert list((jobs / "archive").iterdir())


def test_job_for_another_sink_or_symlink_is_rejected(tmp_path: Path) -> None:
    registry, jobs = _job_sink(tmp_path)
    foreign = jobs / "foreign.json"
    foreign.write_text(json.dumps({"version": 1, "sink": "ssh_ops", "sql": "select 1"}), encoding="utf-8")
    foreign.chmod(0o600)
    dispatcher = PassboltSinkDispatcher(registry)
    with pytest.raises(PermissionError):
        dispatcher.load_job("pg_ro", "foreign")
    target = tmp_path / "real.json"
    target.write_text(json.dumps({"version": 1, "sink": "pg_ro", "sql": "select 1"}), encoding="utf-8")
    link = jobs / "linked.json"
    link.symlink_to(target)
    with pytest.raises(PermissionError):
        dispatcher.load_job("pg_ro", "linked")


def test_job_size_and_permissions_are_bounded(tmp_path: Path) -> None:
    registry, jobs = _job_sink(tmp_path, max_bytes=16)
    big = jobs / "big.json"
    big.write_text(json.dumps({"sql": "select 1"}), encoding="utf-8")
    big.chmod(0o600)
    dispatcher = PassboltSinkDispatcher(registry)
    with pytest.raises(PermissionError):
        dispatcher.load_job("pg_ro", "big")
    readable = jobs / "readable.json"
    readable.write_text(json.dumps({"sql": "select 1"}), encoding="utf-8")
    readable.chmod(0o644)
    with pytest.raises(PermissionError):
        dispatcher.load_job("pg_ro", "readable")


def test_job_requires_configured_private_directory(tmp_path: Path) -> None:
    registry, jobs = _job_sink(tmp_path)
    jobs.chmod(0o755)
    path = jobs / "abc123.json"
    path.write_text(json.dumps({"sql": "select 1"}), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(ProviderError):
        PassboltSinkDispatcher(registry).load_job("pg_ro", "abc123")


@pytest.mark.asyncio
async def test_delivery_envelope_is_derived_from_the_record_uri(tmp_path: Path) -> None:
    output = tmp_path / "envelope.json"
    registry = tmp_path / "sinks.json"
    python = str(Path(sys.executable).resolve())  # noqa: ASYNC240
    _registry(
        registry,
        {
            "pg_ro": {
                "kind": "secure_fill",
                "command": [
                    python,
                    "-c",
                    "import sys;open(sys.argv[1],'w').write(sys.stdin.read())",
                    str(output),
                ],
                "executable_sha256": _sha256(Path(python)),
                "default_port": 5432,
                "default_database": "postgres",
            }
        },
    )
    delivered = await PassboltSinkDispatcher(registry).deliver(
        "pg_ro",
        resource_id="33333333-3333-4333-8333-333333333333",
        username="operator",
        password="sink-only-value",
        target_url="https://db.example:443/app",
        job={"version": 1, "sql": "select 1"},
        job_sha256="a" * 64,
    )
    assert delivered is True
    envelope = json.loads(output.read_text(encoding="utf-8"))
    assert envelope["target"] == {
        "uri": "https://db.example:443/app",
        "scheme": "https",
        "host": "db.example",
        "port": 443,
        "path": "/app",
        "database": "app",
    }
    assert envelope["job_sha256"] == "a" * 64
    assert envelope["password"] == "sink-only-value"


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_pg_guard_accepts_read_only_sql() -> None:
    for sql in (
        "select 1",
        "SELECT now(), current_user",
        "with x as (select 1) select * from x",
        "select 'set; copy; do' as literal",
        "select * from t where id = 1;",
        "values (1), (2)",
    ):
        validate_readonly_sql(sql)


@pytest.mark.parametrize(
    "sql",
    [
        "set role postgres",
        "select 1; drop table t",
        "copy (select 1) to program 'id'",
        "do $$ begin perform 1; end $$",
        "call proc()",
        "select pg_read_file('/etc/passwd')",
        "select lo_export(1, '/tmp/x')",
        "with x as (delete from t returning *) select * from x",
        "select * into new_table from t",
        "select nextval('s')",
        "begin",
        "",
    ],
)
def test_pg_guard_rejects_writes_and_unsafe_calls(sql: str) -> None:
    with pytest.raises(JobError):
        validate_readonly_sql(sql)


def test_pg_job_limits() -> None:
    job = validate_pg_job({"version": 1, "sink": "pg_ro", "sql": "select 1"})
    assert job["max_rows"] == 200 and job["statement_timeout_ms"] == 15_000
    with pytest.raises(JobError):
        validate_pg_job({"version": 1, "sink": "pg_ro", "sql": "select 1", "max_rows": 5000})
    with pytest.raises(JobError):
        validate_pg_job({"version": 1, "sink": "ssh_ops", "sql": "select 1"})


PROFILES = {
    "deploy": {
        "commands": [["systemctl", "status", "nginx"]],
        "upload_dirs": ["/opt/deploy"],
        "allow_overwrite": False,
        "allow_sudo": False,
        "max_bytes": 1024,
    }
}


def test_ssh_job_profile_allowlist() -> None:
    job = ssh_guard.validate_ssh_job(
        {
            "version": 1,
            "sink": "ssh_ops",
            "profile": "deploy",
            "commands": [["systemctl", "status", "nginx"]],
            "uploads": [{"local": "app.tgz", "remote": "/opt/deploy/app.tgz"}],
        },
        adhoc=False,
        profiles=PROFILES,
    )
    assert job["allow_overwrite"] is False and job["max_bytes"] == 1024
    with pytest.raises(SinkError):
        ssh_guard.validate_ssh_job(
            {
                "version": 1,
                "sink": "ssh_ops",
                "profile": "deploy",
                "commands": [["rm", "-rf", "/"]],
            },
            adhoc=False,
            profiles=PROFILES,
        )
    with pytest.raises(SinkError):
        ssh_guard.validate_ssh_job(
            {
                "version": 1,
                "sink": "ssh_ops",
                "profile": "deploy",
                "commands": [["systemctl", "status", "nginx"]],
                "uploads": [{"local": "app.tgz", "remote": "/etc/passwd"}],
            },
            adhoc=False,
            profiles=PROFILES,
        )
    with pytest.raises(SinkError):
        ssh_guard.validate_ssh_job(
            {
                "version": 1,
                "sink": "ssh_ops",
                "profile": "deploy",
                "commands": [["sudo", "systemctl", "restart", "nginx"]],
            },
            adhoc=False,
            profiles=PROFILES,
        )


def test_ssh_adhoc_allows_other_commands_but_requires_matching_sink() -> None:
    job = ssh_guard.validate_ssh_job(
        {"version": 1, "sink": "ssh_adhoc", "commands": [["uptime"]]},
        adhoc=True,
        profiles=None,
    )
    assert job["commands"] == [["uptime"]]
    with pytest.raises(JobError):
        ssh_guard.validate_ssh_job(
            {"version": 1, "sink": "ssh_ops", "commands": [["uptime"]]},
            adhoc=True,
            profiles=None,
        )
    with pytest.raises(SinkError):
        ssh_guard.validate_ssh_job(
            {"version": 1, "sink": "ssh_adhoc", "uploads": [{"local": "x", "remote": "/opt/x"}]},
            adhoc=True,
            profiles=None,
        )


def test_ssh_upload_root_containment(tmp_path: Path) -> None:
    root = tmp_path / "upload"
    root.mkdir(mode=0o700)
    inside = root / "app.tgz"
    inside.write_bytes(b"payload")
    assert ssh_guard.local_path("app.tgz", root) == inside
    outside = tmp_path / "secret"
    outside.write_bytes(b"payload")
    with pytest.raises(Denied):
        ssh_guard.local_path(str(outside), root)
    link = root / "link"
    link.symlink_to(outside)
    with pytest.raises(Denied):
        ssh_guard.local_path("link", root)


def test_web_guard_is_data_driven() -> None:
    target = {"host": "a.example", "port": 443, "path": "/login"}
    assert web_guard.build_plan({}, target) == {"mode": "heuristic"}
    document = {
        "profiles": {
            "a": {
                "match": {"host": "a.example", "path_prefix": "/login"},
                "steps": [
                    {"action": "fill", "selector": "#user", "value_ref": "username"},
                    {"action": "press", "key": "Enter"},
                ],
            }
        }
    }
    plan = web_guard.build_plan(document, target)
    assert plan["mode"] == "profile" and plan["steps"][0]["selector"] == "#user"
    with pytest.raises(InputError):
        web_guard.validate_step({"action": "eval", "selector": "x"})
    with pytest.raises(InputError):
        web_guard.validate_step(
            {"action": "fill", "selector": "javascript:alert(1)", "value_ref": "username"}
        )
    with pytest.raises(InputError):
        web_guard.validate_step({"action": "press", "key": "F12"})
    with pytest.raises(InputError):
        web_guard.validate_step({"action": "fill", "selector": "#x", "value_ref": "secret"})


def test_web_guard_requires_exactly_one_tab() -> None:
    target = {"host": "a.example", "port": 443, "path": "/login"}
    page = {"type": "page", "url": "https://a.example/login", "webSocketDebuggerUrl": "ws://x"}
    assert web_guard.pick_page([page], target) == page
    assert web_guard.pick_page([], target) is None
    other_port = {"type": "page", "url": "https://a.example:8443/login"}
    assert web_guard.pick_page([page, other_port], target) == page
    duplicate = {"type": "page", "url": "https://a.example/login?step=2"}
    with pytest.raises(web_guard.TargetError):
        web_guard.pick_page([page, duplicate], target)


def test_web_guard_follows_a_browser_upgrade_between_80_and_443() -> None:
    """A record stored as http can legitimately face a tab the browser upgraded."""
    http_target = {"host": "a.example", "port": 80, "path": "/login"}
    upgraded = {"type": "page", "url": "https://a.example/login", "webSocketDebuggerUrl": "ws://x"}
    assert web_guard.pick_page([upgraded], http_target) == upgraded
    https_target = {"host": "a.example", "port": 443, "path": "/login"}
    plain = {"type": "page", "url": "http://a.example/login", "webSocketDebuggerUrl": "ws://x"}
    assert web_guard.pick_page([plain], https_target) == plain
    exact_first = {"type": "page", "url": "http://a.example/login", "webSocketDebuggerUrl": "ws://p"}
    assert web_guard.pick_page([exact_first, upgraded], http_target) == exact_first
    # Any other port is a different target, never an upgrade.
    elsewhere = {"type": "page", "url": "https://a.example:8443/x"}
    assert web_guard.pick_page([elsewhere], http_target) is None


def test_web_guard_selects_a_tab_by_marker() -> None:
    target = {"host": "a.example", "port": 443, "path": "/app"}
    first = {
        "type": "page",
        "url": "https://a.example/app/?pb=u-one#/auth",
        "webSocketDebuggerUrl": "ws://one",
    }
    second = {
        "type": "page",
        "url": "https://a.example/app/?pb=u-two#/auth",
        "webSocketDebuggerUrl": "ws://two",
    }
    assert web_guard.pick_page([first, second], target, "u-one") == first
    assert web_guard.pick_page([first, second], target, "u-two") == second
    with pytest.raises(web_guard.TargetError):
        web_guard.pick_page([first, second], target, "u-three")
    with pytest.raises(web_guard.TargetError):
        web_guard.pick_page([first, second], target)


def _install(tmp_path: Path, only: str = "login_fill,pg_ro") -> tuple[Path, Path, Path]:
    dest = tmp_path / "sinks"
    config = tmp_path / "sinks.json"
    state = tmp_path / "state"
    config.write_text(json.dumps({"sinks": {}, "policies": {"default": {}}}), encoding="utf-8")
    config.chmod(0o600)
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "install_sinks.py"),
            "--dest",
            str(dest),
            "--config",
            str(config),
            "--state",
            str(state),
            "--only",
            only,
            "--python",
            f"login_fill={sys.executable}",
            "--python",
            f"pg_ro={sys.executable}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return dest, config, state


def test_install_sinks_pins_entrypoint_and_bundle(tmp_path: Path) -> None:
    dest, config, state = _install(tmp_path)
    document = json.loads(config.read_text(encoding="utf-8"))
    assert document["version"] == 3
    for name, script in (("login_fill", "login_fill.py"), ("pg_ro", "pg_query.py")):
        assert document["sinks"][name]["executable_sha256"] == _sha256(dest / script)
        assert len(document["sinks"][name]["bundle_sha256"]) == 64
    assert stat.S_IMODE((dest / "login_fill.py").stat().st_mode) == 0o700
    assert (dest / "login_fill.py").read_text(encoding="utf-8").startswith(f"#!{sys.executable}")
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert (state / "jobs").is_dir() and os.access(state / "upload", os.W_OK)


def test_bundle_hash_detects_package_tampering(tmp_path: Path) -> None:
    dest, config, _ = _install(tmp_path)
    document = json.loads(config.read_text(encoding="utf-8"))
    dispatcher = PassboltSinkDispatcher(config)
    dispatcher._command(document["sinks"]["login_fill"])
    (dest / "passbolt_sinkkit" / "guards" / "sql.py").write_text("# tampered\n", encoding="utf-8")
    with pytest.raises(ProviderError, match="bundle hash"):
        dispatcher._command(document["sinks"]["login_fill"])


def test_cli_reports_invalid_job_without_dependencies(tmp_path: Path) -> None:
    result_dir = tmp_path / "results"
    envelope = {
        "resource_id": "x",
        "username": "u",
        "password": "p",
        "target": {"host": "db", "port": 5432, "database": "postgres"},
        "job": {"version": 1, "sink": "pg_ro", "sql": "set role postgres"},
    }
    completed = subprocess.run(
        [sys.executable, str(SINKS / "pg_query.py"), "--result-dir", str(result_dir)],
        input=json.dumps(envelope),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 2
    payload = json.loads((result_dir / "pg_ro-last.json").read_text(encoding="utf-8"))
    assert payload["status"] == "invalid_job" and payload["exit_code"] == 2


def test_cli_web_requires_a_matching_tab(tmp_path: Path) -> None:
    result_dir = tmp_path / "results"
    envelope = {
        "resource_id": "x",
        "username": "u",
        "password": "p",
        "target": {"host": "no-such-host.invalid", "port": 443, "path": "/"},
    }
    completed = subprocess.run(
        [sys.executable, str(SINKS / "login_fill.py"), "--result-dir", str(result_dir)],
        input=json.dumps(envelope),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode in {3, 9}
    payload = json.loads((result_dir / "login_fill-last.json").read_text(encoding="utf-8"))
    assert "password" not in json.dumps(payload)


def test_cli_composes_guard_executor_and_result(tmp_path: Path, monkeypatch) -> None:
    from passbolt_sinkkit import cli

    seen: dict[str, Any] = {}

    def fake_run(target, plan, values, **kwargs):
        seen.update(target=target, plan=plan, values=values)
        return {"status": "logged_in", "url": "https://a.example/home"}

    monkeypatch.setattr(cli.web_executor, "run", fake_run)
    monkeypatch.setattr(sys, "argv", [str(tmp_path / "login_fill.py")])
    envelope = {
        "username": "operator",
        "password": "sink-only-value",
        "target": {"host": "a.example", "port": 443, "path": "/login"},
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(envelope)))
    code = cli.main("web", ["--result-dir", str(tmp_path / "results")])
    assert code == 0
    assert seen["target"]["host"] == "a.example" and seen["values"]["username"] == "operator"
    payload = json.loads((tmp_path / "results" / "login_fill-last.json").read_text(encoding="utf-8"))
    assert payload["status"] == "logged_in" and payload["exit_code"] == 0
    assert "sink-only-value" not in json.dumps(payload)


def test_sink_package_has_no_import_side_effect_dependencies() -> None:
    module = importlib.util.find_spec("passbolt_sinkkit")
    assert module is not None
