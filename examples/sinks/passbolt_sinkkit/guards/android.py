"""Android login guard: profiles, selectors and the step language. No device access here."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from passbolt_sinkkit.errors import Denied, InputError

MAX_PROFILE_BYTES = 262_144
MAX_STEPS = 20
MAX_SELECTOR = 200
ACTIONS = frozenset({"fill", "click", "press", "wait"})
SELECTOR_KEYS = frozenset({"text", "resource_id", "class_name", "description", "xpath"})
PRESS_KEYS = frozenset({"enter", "back", "home", "delete", "search"})
VALUE_REFS = frozenset({"username", "password"})
PACKAGE_RE = re.compile(r"[a-z][a-z0-9_]*(\.[a-z0-9_]+)+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
DEFAULT_TIMEOUT_MS = 15_000
MIN_TIMEOUT_MS = 500
MAX_TIMEOUT_MS = 60_000
# How long to wait for the login form itself before declaring the app is not on a login screen.
DEFAULT_LOGIN_WAIT_MS = 3_000
MAX_LOGIN_WAIT_MS = 15_000


def _posix_mode_gate() -> bool:
    """POSIX mode bits gate custody on Linux; Windows relies on the profile's ACLs.

    This is a named seam, not a global ``os.name`` check, so the behaviour can be exercised
    in tests without pretending the whole interpreter is Windows.
    """
    return os.name != "nt"


def load_profiles(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    file = Path(path)
    try:
        info = file.lstat()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise Denied("android profiles file is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PROFILE_BYTES:
        raise Denied("android profiles file is invalid")
    if _posix_mode_gate() and info.st_mode & 0o077:
        raise Denied("android profiles file permissions are unsafe")
    try:
        document = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Denied("android profiles file is invalid") from exc
    if not isinstance(document, dict) or not isinstance(document.get("profiles"), dict):
        raise Denied("android profiles file is invalid")
    return document["profiles"]


def package_of(target: dict[str, Any]) -> str:
    package = str(target.get("host") or "")
    if PACKAGE_RE.fullmatch(package) is None:
        raise InputError("android:// record must name a package, for example android://ru.itserv.skr")
    return package


def activity_of(target: dict[str, Any]) -> str | None:
    path = str(target.get("path") or "").strip("/")
    return path or None


def validate_selector(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) != 1:
        raise InputError("android selector must name exactly one of: " + ", ".join(sorted(SELECTOR_KEYS)))
    key, item = next(iter(value.items()))
    if key not in SELECTOR_KEYS:
        raise InputError("android selector must name exactly one of: " + ", ".join(sorted(SELECTOR_KEYS)))
    if not isinstance(item, str) or not item or len(item) > MAX_SELECTOR:
        raise InputError("android selector value is invalid")
    if _CONTROL.search(item) or item.strip().lower().startswith("javascript:"):
        raise InputError("android selector value is invalid")
    if key == "xpath" and (not item.startswith("//") or ".." in item):
        # A login profile never needs the parent axis; keep the selector inside the hierarchy.
        raise InputError("android xpath selector must be absolute")
    return {key: item}


def _timeout(value: Any) -> int:
    timeout = DEFAULT_TIMEOUT_MS if value is None else value
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or not MIN_TIMEOUT_MS <= timeout <= MAX_TIMEOUT_MS
    ):
        raise InputError("timeout_ms is out of range")
    return timeout


def validate_step(step: Any) -> dict[str, Any]:
    if not isinstance(step, dict) or not isinstance(step.get("action"), str):
        raise InputError("android step must have an action")
    action = step["action"]
    if action not in ACTIONS:
        raise InputError(f"unsupported android action: {action}")
    if action == "fill":
        reference = step.get("value_ref")
        if reference not in VALUE_REFS:
            raise InputError("fill needs a known value_ref")
        return {
            "action": action,
            "selector": validate_selector(step.get("selector")),
            "value_ref": reference,
            "timeout_ms": _timeout(step.get("timeout_ms")),
        }
    if action == "click":
        return {
            "action": action,
            "selector": validate_selector(step.get("selector")),
            "timeout_ms": _timeout(step.get("timeout_ms")),
        }
    if action == "press":
        key = step.get("key")
        if key not in PRESS_KEYS:
            raise InputError("press key is not allowed")
        return {"action": action, "key": key}
    return {
        "action": "wait",
        "selector": validate_selector(step.get("selector")),
        "timeout_ms": _timeout(step.get("timeout_ms")),
    }


def validate_verify(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise InputError("android verify block is invalid")
    present = value.get("present")
    absent = value.get("absent")
    if (present is None) == (absent is None):
        raise InputError("android verify needs exactly one of present/absent")
    parsed: dict[str, Any] = {"timeout_ms": _timeout(value.get("timeout_ms"))}
    parsed["present" if present is not None else "absent"] = validate_selector(
        present if present is not None else absent
    )
    return parsed


def match_profile(profile: Any, package: str, activity: str | None) -> bool:
    if not isinstance(profile, dict):
        return False
    selector = profile.get("match")
    if not isinstance(selector, dict):
        return False
    if str(selector.get("package") or "").lower() != package:
        return False
    wanted_activity = selector.get("activity")
    if wanted_activity is None or activity is None:
        # The record may name only the package (android://pkg or android://pkg/); the app decides
        # which activity it shows. An activity in the URI narrows the match, it is not required.
        return True
    return str(wanted_activity).strip(".").lower() == activity.strip(".").lower()


def build_plan(document: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    package = package_of(target)
    activity = activity_of(target)
    profiles = document.get("profiles") if isinstance(document.get("profiles"), dict) else document
    for profile in profiles.values():
        if not match_profile(profile, package, activity):
            continue
        steps = profile.get("steps")
        if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
            raise InputError("android profile steps are invalid")
        login_wait = profile.get("login_wait_ms", DEFAULT_LOGIN_WAIT_MS)
        if (
            isinstance(login_wait, bool)
            or not isinstance(login_wait, int)
            or not 0 <= login_wait <= MAX_LOGIN_WAIT_MS
        ):
            raise InputError("login_wait_ms is out of range")
        plan: dict[str, Any] = {
            "mode": "profile",
            "package": package,
            "activity": activity,
            "steps": [validate_step(step) for step in steps],
            "timeout_ms": _timeout(profile.get("timeout_ms")),
            "login_wait_ms": login_wait,
        }
        verify = validate_verify(profile.get("verify"))
        if verify is not None:
            plan["verify"] = verify
        return plan
    # No profile: fall back to the generic heuristic (visible password field + log in button).
    return {
        "mode": "heuristic",
        "package": package,
        "activity": activity,
        "timeout_ms": DEFAULT_TIMEOUT_MS,
        "login_wait_ms": DEFAULT_LOGIN_WAIT_MS,
    }
