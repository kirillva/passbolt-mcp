"""Web guard: page selection and a small declarative login-step language.

Site-specific behaviour lives in ``web-profiles.json`` data, never in code. A
profile is a list of whitelisted steps (fill/click/press/wait/expect/otp) with
CSS selectors. Without a matching profile the executor falls back to the
generic heuristic (visible password field + login field + submit).
"""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from passbolt_sinkkit.errors import Denied, InputError

MAX_TARGETS = 200
MAX_STEPS = 30
MAX_SELECTOR = 200
MAX_PROFILE_BYTES = 262_144
ACTIONS = frozenset({"fill", "click", "press", "wait", "expect", "otp"})
VALUE_REFS = frozenset({"username", "password", "totp"})
PRESS_KEYS = frozenset({"Enter", "Tab", "Escape"})
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def load_profiles(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    file = Path(path)
    try:
        info = file.lstat()
    except FileNotFoundError:
        # Web profiles refine selectors only; the generic heuristic stays safe.
        return {}
    except OSError as exc:
        raise Denied("web profiles file is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PROFILE_BYTES:
        raise Denied("web profiles file is invalid")
    if info.st_mode & 0o077:
        raise Denied("web profiles file permissions are unsafe")
    try:
        document = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Denied("web profiles file is invalid") from exc
    if not isinstance(document, dict) or not isinstance(document.get("profiles"), dict):
        raise Denied("web profiles file is invalid")
    return document["profiles"]


def page_origin(url: str) -> tuple[str, int]:
    parsed = urlsplit(url)
    default_port = 443 if parsed.scheme == "https" else 80
    return (parsed.hostname or "").lower(), parsed.port or default_port


def path_matches(path: str, prefix: str) -> bool:
    return prefix in {"", "/"} or path.startswith(prefix)


def pick_page(targets: list[Any], target: dict[str, Any]) -> dict[str, Any] | None:
    """Exactly one tab must match host, port and the record path prefix."""
    if len(targets) > MAX_TARGETS:
        raise InputError("too many browser targets")
    pages = []
    for item in targets:
        if not isinstance(item, dict) or item.get("type") != "page":
            continue
        if page_origin(str(item.get("url") or "")) != (target["host"], target["port"]):
            continue
        pages.append(item)
    if not pages:
        return None
    prefix = target["path"] if target["path"] not in {"", "/"} else ""
    if prefix:
        exact = [
            page
            for page in pages
            if path_matches(urlsplit(str(page.get("url"))).path, prefix)
        ]
        if exact:
            pages = exact
    return pages[0] if len(pages) == 1 else None


def _selector(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_SELECTOR:
        raise InputError("selector is invalid")
    if _CONTROL.search(value) or value.strip().lower().startswith("javascript:"):
        raise InputError("selector is invalid")
    return value


def _timeout(value: Any) -> int:
    timeout = 10_000 if value is None else value
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 100 <= timeout <= 30_000:
        raise InputError("timeout_ms is out of range")
    return timeout


def validate_step(step: Any) -> dict[str, Any]:
    if not isinstance(step, dict) or not isinstance(step.get("action"), str):
        raise InputError("step must have an action")
    action = step["action"]
    if action not in ACTIONS:
        raise InputError(f"unsupported action: {action}")
    if action == "fill":
        reference = step.get("value_ref")
        if reference not in VALUE_REFS:
            raise InputError("fill needs a known value_ref")
        return {"action": action, "selector": _selector(step.get("selector")), "value_ref": reference}
    if action in {"click", "otp"}:
        parsed = {"action": action, "selector": _selector(step.get("selector"))}
        if action == "otp":
            parsed["timeout_ms"] = _timeout(step.get("timeout_ms"))
        return parsed
    if action == "press":
        key = step.get("key")
        if key not in PRESS_KEYS:
            raise InputError("press key is not allowed")
        return {"action": action, "key": key}
    if action == "wait":
        return {
            "action": action,
            "selector": _selector(step.get("selector")),
            "timeout_ms": _timeout(step.get("timeout_ms")),
        }
    url_not = step.get("url_not")
    url_contains = step.get("url_contains")
    if url_not is None and url_contains is None:
        raise InputError("expect needs url_not or url_contains")
    parsed = {"action": action, "timeout_ms": _timeout(step.get("timeout_ms"))}
    if url_not is not None:
        if not isinstance(url_not, str) or not url_not or len(url_not) > 2_048:
            raise InputError("url_not is invalid")
        parsed["url_not"] = url_not
    if url_contains is not None:
        if not isinstance(url_contains, str) or not url_contains or len(url_contains) > 2_048:
            raise InputError("url_contains is invalid")
        parsed["url_contains"] = url_contains
    return parsed


def match_profile(profile: Any, target: dict[str, Any]) -> bool:
    if not isinstance(profile, dict):
        return False
    selector = profile.get("match")
    if not isinstance(selector, dict):
        return False
    host = selector.get("host")
    if not isinstance(host, str) or host.lower() != target["host"]:
        return False
    prefix = selector.get("path_prefix") or "/"
    if not isinstance(prefix, str):
        return False
    return path_matches(target["path"], prefix)


def select_profile(document: dict[str, Any], target: dict[str, Any]) -> dict[str, Any] | None:
    profiles = document.get("profiles") if isinstance(document.get("profiles"), dict) else document
    for profile in profiles.values():
        if match_profile(profile, target):
            return profile
    default = profiles.get("default")
    if isinstance(default, dict) and (default.get("mode") == "heuristic" or "steps" in default):
        return default
    return None


def build_plan(document: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    profile = select_profile(document, target)
    if not isinstance(profile, dict) or profile.get("mode") == "heuristic":
        return {"mode": "heuristic"}
    steps = profile.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise InputError("profile steps are invalid")
    return {"mode": "profile", "steps": [validate_step(step) for step in steps]}
