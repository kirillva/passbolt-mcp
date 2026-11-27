from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from zai_passbolt import tool_log


def _entries(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _record(state: Path, **overrides: object) -> None:
    payload = {
        "state_path": state,
        "version": "0.7.4",
        "tool": "passbolt_status",
        "outcome": "error",
        "code": "provider_error",
        "error": "ProviderError",
        "hint": None,
        "actor": "local-operator",
        "execution_id": "run-1",
        "duration_ms": 3,
        "arguments": {},
    }
    payload.update(overrides)
    tool_log.record_error(**payload)  # type: ignore[arg-type]


def test_error_log_is_private_jsonl_and_drops_secrets(tmp_path: Path) -> None:
    state = tmp_path / "state" / "passbolt.sqlite"
    _record(
        state,
        tool="passbolt_create_resource",
        code="provider_configuration_invalid",
        error="ProviderConfigurationError",
        hint="store the site as HTTPS",
        arguments={
            "name": "Office",
            "target_url": "https://user:pass@example.com/login?token=x#frag",
            "query": "  Office   wifi  ",
            "secret_source": {"kind": "plaintext", "value": "do-not-log"},
            "fields": {"note": "private-note"},
            "limit": 20,
            "approved": True,
        },
    )
    log = state.parent / "tool-errors.jsonl"
    raw = log.read_text(encoding="utf-8")
    assert "do-not-log" not in raw
    assert "user:pass" not in raw and "token=x" not in raw
    assert "private-note" not in raw

    [entry] = _entries(log)
    assert entry["tool"] == "passbolt_create_resource"
    assert entry["code"] == "provider_configuration_invalid"
    assert entry["hint"] == "store the site as HTTPS"
    assert entry["arguments"]["target_url"] == "https://example.com"
    assert entry["arguments"]["query"] == "Office wifi"
    assert entry["arguments"]["limit"] == 20
    assert entry["arguments"]["approved"] is True
    assert entry["arguments"]["name"] == {"chars": 6}
    assert "secret_source" not in entry["arguments"] and "fields" not in entry["arguments"]
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


def test_site_hint_keeps_the_scheme_but_nothing_private() -> None:
    assert tool_log.safe_site("http://demo.example/arm/x?token=1#f") == "http://demo.example"
    assert tool_log.safe_site("https://u:p@demo.example:8443/x") == "https://demo.example:8443"
    assert tool_log.safe_site("demo.example:8443") == "demo.example:8443"
    assert tool_log.safe_site("ftp://demo.example/x") == "<scheme>://demo.example"
    assert tool_log.safe_site("https://") == "<unparsable>"


def test_log_rotates_by_size_and_every_line_stays_parseable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tool_log, "MAX_FILE_BYTES", 300)
    state = tmp_path / "state" / "passbolt.sqlite"
    for index in range(6):
        _record(state, execution_id=f"run-{index}", arguments={"query": "x" * 80})

    log = state.parent / "tool-errors.jsonl"
    files = sorted(state.parent.glob("tool-errors.jsonl*"))
    assert log.exists() and 1 < len(files) <= tool_log.ROTATED_FILES + 1

    # Oldest first: .2, .1, then the live file. Rotation drops older lines by design.
    ordered = [state.parent / f"tool-errors.jsonl.{index}" for index in range(tool_log.ROTATED_FILES, 0, -1)]
    kept = [
        entry["execution_id"]
        for path in [*ordered, log]
        if path.exists()
        for entry in _entries(path)
    ]
    assert kept and kept[-1] == "run-5"
    assert kept == sorted(kept, key=lambda value: int(value.rsplit("-", 1)[1]))
    assert len(kept) <= tool_log.ROTATED_FILES + 1


def test_operator_can_disable_the_log_and_only_write_it_inside_their_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state" / "passbolt.sqlite"
    monkeypatch.setenv("PASSBOLT_TOOL_LOG", "off")
    _record(state)
    assert not (state.parent / "tool-errors.jsonl").exists()

    monkeypatch.delenv("PASSBOLT_TOOL_LOG")
    outside_home = tmp_path / "elsewhere.jsonl"
    monkeypatch.setenv("PASSBOLT_TOOL_LOG_PATH", str(outside_home))
    _record(state)
    assert not outside_home.exists()
    # An out-of-home override falls back to the private state directory.
    assert (state.parent / "tool-errors.jsonl").exists()

    inside_home = Path.home() / ".cache" / f"passbolt-mcp-test-{os.getpid()}" / "errors.jsonl"
    monkeypatch.setenv("PASSBOLT_TOOL_LOG_PATH", str(inside_home))
    try:
        _record(state)
        assert inside_home.exists() and _entries(inside_home)
    finally:
        if inside_home.parent.exists():
            for path in inside_home.parent.iterdir():
                path.unlink(missing_ok=True)
            inside_home.parent.rmdir()


def test_a_broken_log_never_breaks_the_caller(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = tmp_path / "state" / "passbolt.sqlite"
    monkeypatch.setenv("PASSBOLT_TOOL_LOG_PATH", str(tmp_path / "blocked" / "log.jsonl"))

    def explode(*args: object, **kwargs: object) -> None:
        raise OSError("disk is gone")

    monkeypatch.setattr(tool_log.os, "open", explode)
    _record(state)  # must not raise


def test_log_write_survives_a_platform_without_o_nofollow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Windows has no O_NOFOLLOW: the log must still be written, not raise AttributeError."""
    monkeypatch.delattr(tool_log.os, "O_NOFOLLOW", raising=False)
    _record(tmp_path / "state" / "passbolt.sqlite")
    log = tmp_path / "state" / "tool-errors.jsonl"
    assert log.exists() and _entries(log)
