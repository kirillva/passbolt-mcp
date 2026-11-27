"""Android executor: trusted input into a device over uiautomator2. No policy decisions.

The credential is typed through the accessibility/UiAutomator channel (`set_text`), never
through `adb shell input text`, so it does not appear in a process command line on the host.
"""

from __future__ import annotations

import os
import re
import time
import xml.etree.ElementTree as ElementTree
from typing import Any

from passbolt_sinkkit.errors import (
    AuthRejected,
    FormError,
    InputError,
    MfaRequired,
    RemoteFailure,
    SinkError,
    SinkTimeout,
    TargetError,
)

POLL_SECONDS = 0.5
MAX_NODES = 500

# The app's own refusal, in the wording these stands use (see the web sink for the same idea).
_FAILURE_RE = re.compile(
    r"(неверн|неправильн|ошибк[аи]\s*(входа|авторизаци|логина|пароля)?|доступ\s+запрещ"
    r"|заблокиров|пользовател[ьи]\s+не\s+(найден|авторизов)|не\s+авторизов"
    r"|invalid|incorrect|wrong\s+password|unauthoriz|access\s+denied|forbidden|locked\s*out)",
    re.IGNORECASE,
)
_MFA_RE = re.compile(r"(код|code|otp|2fa|two-factor|подтвержд)", re.IGNORECASE)
_SUBMIT_RE = re.compile(r"^(ок|ok|войти|вход|login|log\s?in|sign\s?in|далее|продолжить)$", re.IGNORECASE)


def _connect(serial: str | None, adb: str | None):
    if adb:
        # adbutils reads this at import time; set it before uiautomator2 is imported.
        os.environ.setdefault("ADBUTILS_ADB_PATH", adb)
    try:
        import uiautomator2 as u2
    except ImportError as exc:
        raise SinkError("uiautomator2 is not installed") from exc
    try:
        return u2.connect(serial) if serial else u2.connect()
    except Exception as exc:  # noqa: BLE001 - provider errors stay opaque
        raise TargetError("android device is unavailable") from exc


def _nodes(device) -> list[dict[str, Any]]:
    try:
        xml = device.dump_hierarchy(compressed=False)
    except Exception as exc:  # noqa: BLE001
        raise RemoteFailure("android ui dump failed") from exc
    if not isinstance(xml, str):
        raise RemoteFailure("android ui dump failed")
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError as exc:
        raise RemoteFailure("android ui dump failed") from exc
    result: list[dict[str, Any]] = []
    for node in root.iter("node"):
        result.append(
            {
                "class": node.get("class") or "",
                "resource_id": node.get("resource-id") or "",
                "text": (node.get("text") or "").strip(),
                "description": (node.get("content-desc") or "").strip(),
                "password": node.get("password") == "true",
                "clickable": node.get("clickable") == "true",
                "enabled": node.get("enabled") != "false",
                "bounds": node.get("bounds") or "",
            }
        )
        if len(result) >= MAX_NODES:
            break
    return result


def _obj(device, selector: dict[str, str]):
    if "xpath" in selector:
        return device.xpath(selector["xpath"])
    kwargs: dict[str, Any] = {}
    if "text" in selector:
        kwargs["text"] = selector["text"]
    if "resource_id" in selector:
        kwargs["resourceId"] = selector["resource_id"]
    if "class_name" in selector:
        kwargs["className"] = selector["class_name"]
    if "description" in selector:
        kwargs["description"] = selector["description"]
    return device(**kwargs)


def _wait(device, selector: dict[str, str], timeout_ms: int) -> Any:
    target = _obj(device, selector)
    try:
        found = target.wait(timeout=timeout_ms / 1000)
    except Exception as exc:  # noqa: BLE001
        raise RemoteFailure("android element lookup failed") from exc
    if not found:
        raise SinkTimeout("android element did not appear")
    return target


def _fill(device, selector: dict[str, str], value: str, timeout_ms: int) -> None:
    target = _wait(device, selector, timeout_ms)
    try:
        target.set_text(value)
    except Exception as exc:  # noqa: BLE001
        raise FormError("android field could not be filled") from exc
    time.sleep(0.2)
    try:
        typed = target.get_text()
    except Exception:  # noqa: BLE001 - readback is best effort
        typed = None
    # A password field answers with its mask ("•••") and some apps transform the login case, so
    # only an *empty* readback means the text never landed. The value itself is never compared.
    if isinstance(typed, str) and not typed:
        raise FormError("android field did not accept the typed text")


def _click(device, selector: dict[str, str], timeout_ms: int) -> None:
    target = _wait(device, selector, timeout_ms)
    try:
        target.click()
    except Exception as exc:  # noqa: BLE001
        raise FormError("android element could not be clicked") from exc
    time.sleep(0.3)


def _state(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    passwords = [n for n in nodes if n["password"] and n["class"].endswith("EditText")]
    texts = [n["text"] for n in nodes if n["text"]] + [n["description"] for n in nodes if n["description"]]
    return {
        "nodes": nodes,
        "texts": texts,
        "passwords": len(passwords),
        "mfa": any(_MFA_RE.search(n["text"] + " " + n["description"]) for n in nodes if n["enabled"]),
    }


def _refusal(state: dict[str, Any]) -> str | None:
    for text in state["texts"]:
        if _FAILURE_RE.search(text):
            return text[:300]
    return None


def _run_steps(device, plan: dict[str, Any], values: dict[str, str]) -> None:
    for step in plan["steps"]:
        action = step["action"]
        if action == "fill":
            value = values.get(step["value_ref"])
            if not isinstance(value, str) or not value:
                raise InputError("no value for the fill step")
            _fill(device, step["selector"], value, step["timeout_ms"])
        elif action == "click":
            _click(device, step["selector"], step["timeout_ms"])
        elif action == "press":
            try:
                device.press(step["key"])
            except Exception as exc:  # noqa: BLE001
                raise FormError("android key press failed") from exc
            time.sleep(0.3)
        elif action == "wait":
            _wait(device, step["selector"], step["timeout_ms"])


def _center(bounds: str) -> tuple[int, int] | None:
    match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
    if not match:
        return None
    x1, y1, x2, y2 = (int(value) for value in match.groups())
    return (x1 + x2) // 2, (y1 + y2) // 2


def _selector_for(node: dict[str, Any]) -> dict[str, str] | None:
    if node["resource_id"]:
        return {"resource_id": node["resource_id"]}
    if node["text"]:
        return {"text": node["text"]}
    if node["description"]:
        return {"description": node["description"]}
    return None


def _heuristic_form(nodes: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Resolve a two-field login form: a login field, a password field and a submit control."""
    edits = [n for n in nodes if n["class"].endswith("EditText") and n["enabled"]]
    passwords = [n for n in edits if n["password"]]
    if not passwords:
        return None
    password = passwords[0]
    before = [n for n in edits if n is not password and nodes.index(n) < nodes.index(password)]
    login = before[-1] if before else None
    submit = next(
        (
            n
            for n in nodes
            if n["clickable"]
            and (n["text"] or n["description"])
            and _SUBMIT_RE.match(n["text"] or n["description"])
        ),
        None,
    )
    if login is None or submit is None:
        return None
    return {
        "login": _selector_for(login) or {"class_name": login["class"]},
        "password": _selector_for(password) or {"class_name": password["class"]},
        "submit": _selector_for(submit),
        "submit_point": _center(submit["bounds"]),
    }


def _run_heuristic(device, values: dict[str, str]) -> None:
    form = _heuristic_form(_nodes(device))
    if form is None:
        raise FormError("android login form is not recognised; add a profile for this app")
    _fill(device, form["login"], values["username"], 10_000)
    _fill(device, form["password"], values["password"], 10_000)
    if form["submit"] is not None:
        _click(device, form["submit"], 10_000)
        return
    if form["submit_point"] is None:
        raise FormError("android login button has no usable bounds")
    device.click(*form["submit_point"])
    time.sleep(0.3)


def _first_fill_selector(plan: dict[str, Any]) -> dict[str, str] | None:
    for step in plan["steps"]:
        if step["action"] == "fill":
            return step["selector"]
    return None


def _login_form_ready(device, plan: dict[str, Any], wait_ms: int) -> bool:
    """Wait a short, bounded time for the login form; an absent form is a final answer."""
    deadline = time.monotonic() + wait_ms / 1000
    while True:
        if plan["mode"] == "profile":
            selector = _first_fill_selector(plan)
            ready = True if selector is None else bool(_obj(device, selector).exists)
        else:
            ready = _heuristic_form(_nodes(device)) is not None
        if ready:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(POLL_SECONDS)


def _classify(device, plan: dict[str, Any]) -> dict[str, Any]:
    deadline = time.monotonic() + plan["timeout_ms"] / 1000
    verify = plan.get("verify") if isinstance(plan.get("verify"), dict) else None
    while True:
        state = _state(_nodes(device))
        refused = _refusal(state)  # the app's own error text, when it shows one
        if refused:
            raise AuthRejected(refused)
        if state["mfa"]:
            raise MfaRequired("verification is required")
        settled = False
        if verify is not None:
            wait_ms = verify["timeout_ms"]
            if "present" in verify:
                try:
                    settled = _wait(device, verify["present"], wait_ms).exists
                except SinkTimeout:
                    settled = False
            else:
                try:
                    gone = _obj(device, verify["absent"]).wait_gone(timeout=wait_ms / 1000)
                except Exception:  # noqa: BLE001
                    gone = False
                settled = bool(gone)
        else:
            settled = state["passwords"] == 0
        if settled:
            current = {}
            try:
                current = device.app_current() or {}
            except Exception:  # noqa: BLE001 - informational only
                current = {}
            return {
                "status": "logged_in",
                "package": plan["package"],
                "activity": str(current.get("activity") or plan.get("activity") or ""),
            }
        if time.monotonic() >= deadline:
            # Universal signal: a successful sign-in removes the login fields. If they are still
            # there, the attempt failed — whatever the app did or did not say about it.
            raise AuthRejected("the login fields are still on screen")
        time.sleep(POLL_SECONDS)


def run(
    target: dict[str, Any],
    username: str,
    password: str,
    plan: dict[str, Any],
    *,
    device: str | None = None,
    adb: str | None = None,
) -> dict[str, Any]:
    serial = device or os.environ.get("ANDROID_SERIAL") or None
    connection = _connect(serial, adb)
    try:
        current = connection.app_current() or {}
    except Exception:  # noqa: BLE001
        # Right after a cold start the on-device service can answer "ApplicationSharedMemory not
        # initialized"; a fresh connection clears it (the first call fails, the next one works).
        time.sleep(1.5)
        connection = _connect(serial, adb)
        try:
            current = connection.app_current() or {}
        except Exception as exc:  # noqa: BLE001
            raise TargetError("android device is unavailable") from exc
    package = str(current.get("package") or "")
    if package != plan["package"]:
        raise TargetError(
            f"target app {plan['package']} is not in the foreground; open it before delivering"
        )
    wait_ms = int(plan.get("login_wait_ms") or 0)
    if not _login_form_ready(connection, plan, wait_ms):
        # The app is in the foreground but shows no login form: already signed in, or a different
        # screen. Waiting the full classification timeout there would only waste ~20 s.
        raise FormError("login form is not visible; the app may already be signed in")
    values = {"username": username, "password": password}
    if plan["mode"] == "profile":
        _run_steps(connection, plan, values)
    else:
        _run_heuristic(connection, values)
    return _classify(connection, plan)
