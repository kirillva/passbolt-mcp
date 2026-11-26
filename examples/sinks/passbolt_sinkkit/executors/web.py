#!/usr/bin/env python3
"""Web executor: trusted-input CDP actions. No policy decisions live here."""

from __future__ import annotations

import contextlib
import fcntl
import fnmatch
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from passbolt_sinkkit.errors import (
    AccountMismatch,
    AuthRejected,
    AuthUnconfirmed,
    FormError,
    InputError,
    MfaRequired,
    RemoteFailure,
    SinkError,
    SinkTimeout,
    TargetError,
)
from passbolt_sinkkit.guards.web import pick_page

DEFAULT_CDP = "http://127.0.0.1:9222"
POLL_SECONDS = 0.4
# How long to wait for a site that neither redirects nor answers before admitting
# that the outcome is unknown, instead of reporting a login nobody confirmed.
SETTLE_SECONDS = 6.0

COORDS_JS = r"""(() => {
  const vis = el => el && el.offsetParent !== null && !el.disabled;
  const pw = [...document.querySelectorAll('input[type="password"]')].filter(vis)[0];
  if (!pw) return 'no-password-field';
  const texts = [...document.querySelectorAll('input[type="text"], input[type="email"], input[type="tel"], input:not([type])')]
    .filter(el => vis(el) && el.type !== 'hidden');
  let login = texts.find(el => /user|login|email|mail|account|учет|логин/i.test(
      (el.name || '') + (el.id || '') + (el.getAttribute('placeholder') || '') + (el.getAttribute('aria-label') || '')));
  if (!login && texts.length) {
    const before = texts.filter(el => pw.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_PRECEDING);
    login = before[before.length - 1] || texts[0];
  }
  if (!login) return 'no-login-field';
  const scope = pw.form || pw.closest('form') || document;
  const submit = [...scope.querySelectorAll('button[type="submit"], input[type="submit"]')]
    .concat([...scope.querySelectorAll('button')].filter(b =>
      /войти|вход|log\s?in|sign\s?in|submit|подтвердить/i.test(b.textContent || '')))
    .filter(vis)[0];
  if (!submit) return 'no-submit';
  const c = el => { const r = el.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; };
  return JSON.stringify({ login: c(login), pw: c(pw), submit: c(submit), url: location.href });
})()"""

FOCUS_JS = r"""(() => {
  const el = document.activeElement;
  if (!el) return JSON.stringify({ x: -1, y: -1 });
  const r = el.getBoundingClientRect();
  return JSON.stringify({ x: r.x + r.width / 2, y: r.y + r.height / 2 });
})()"""

STATE_JS = r"""(() => {
  const vis = el => el && el.offsetParent !== null && !el.disabled;
  const pwLeft = [...document.querySelectorAll('input[type="password"]')].filter(vis).length;
  const otp = [...document.querySelectorAll('input')].filter(el =>
    vis(el) && (/one-time-code/i.test(el.autocomplete || '') ||
      /otp|code|2fa|verification/i.test((el.name || '') + (el.id || '') + (el.getAttribute('placeholder') || ''))));
  const text = (document.body ? document.body.innerText : '') || '';
  const mfa = otp.length > 0 || /(two-factor|2fa|verification code|authenticator|код подтверждения)/i.test(text);
  const alert = [...document.querySelectorAll('[role="alert"], .error, .alert-danger, [data-error]')]
    .filter(vis).map(el => (el.innerText || '').trim()).filter(Boolean)[0] || '';
  const dialogNodes = [...document.querySelectorAll(
    '[role="alertdialog"], [role="dialog"], .x-message-box, .x-window, .x-form-invalid-under,'
    + ' .x-form-invalid-tip, .x-tip, .ant-message, .ant-modal-body, .modal.show, .toast, .notification')]
    .filter(vis).map(el => (el.innerText || '').trim()).filter(t => t && t.length <= 300);
  const dialogs = dialogNodes.slice(0, 8);
  return JSON.stringify({ pwLeft, url: location.href, mfa, alert: alert.slice(0, 300),
    dialog: (dialogs[0] || '').slice(0, 300), dialogs: dialogs.map(t => t.slice(0, 300)) });
})()"""

# A page that keeps the login form on screen after a submit is not logged in; a
# toolkit dialog that says so is the site's own refusal, and the caller deserves
# that sentence instead of a "logged_in" it cannot trust.
_AUTH_FAILURE_RE = re.compile(
    r"(неверн|неправильн|не существует|не найден|заблокиров|неактивн|придум[ау]н|истёк|истек"
    r"|ошибк[аи]\s+(авторизаци|входа|логина|пароля|учёт|учет|аутентифик)"
    r"|доступ\s+(запрещ|отказан)|не\s+авторизов|несовпад"
    r"|invalid|incorrect|wrong\s+(password|login)|unauthoriz|not\s+authorized|access\s+denied"
    r"|forbidden|locked\s*out|account\s+(is\s+)?(disabled|locked))",
    re.IGNORECASE,
)


def failure_text(state: dict[str, Any]) -> str:
    """The site's refusal, if there is one: an explicit alert, or a dialog that reads like one."""
    alert = str(state.get("alert") or "").strip()
    if alert:
        return alert[:300]
    listed = state.get("dialogs")
    texts = [str(item) for item in listed] if isinstance(listed, list) else []
    if not texts and state.get("dialog"):
        texts = [str(state.get("dialog"))]
    # The login window is a dialog too and usually comes first in the DOM, so scan every
    # candidate and take the one that reads like a refusal rather than the earliest one.
    for text in texts:
        stripped = " ".join(text.split())
        if stripped and _AUTH_FAILURE_RE.search(stripped):
            return stripped[:300]
    return ""


def login_outcome(state: dict[str, Any], start_url: str = "") -> tuple[str, str]:
    """Classify the page after a submit: logged_in, mfa, rejected or unconfirmed."""
    refused = failure_text(state)
    if refused:
        return "rejected", refused
    if state.get("mfa"):
        return "mfa", ""
    try:
        pw_left = int(state.get("pwLeft") or 0)
    except (TypeError, ValueError):
        pw_left = 0
    if pw_left == 0:
        return "logged_in", ""
    url = str(state.get("url") or "")
    if start_url and url and url != start_url:
        return "logged_in", ""
    return "unconfirmed", "the login form is still on screen"



def _selector_point_js(selector: str) -> str:
    return (
        "(() => {"
        f" const el = document.querySelector({json.dumps(selector)});"
        " if (!el) return 'missing';"
        " el.scrollIntoView({block: 'center', inline: 'center'});"
        " const r = el.getBoundingClientRect();"
        " if (r.width === 0 || r.height === 0) return 'hidden';"
        " return JSON.stringify({x: r.x + r.width / 2, y: r.y + r.height / 2});"
        "})()"
    )


def _selector_visible_js(selector: str) -> str:
    return (
        "(() => {"
        f" const el = document.querySelector({json.dumps(selector)});"
        " if (!el) return false;"
        " const r = el.getBoundingClientRect();"
        " return r.width > 0 && r.height > 0;"
        "})()"
    )


class Cdp:
    def __init__(self, socket) -> None:
        self.socket = socket
        self.next_id = 0

    def call(self, method: str, **params: Any) -> dict:
        self.next_id += 1
        identifier = self.next_id
        self.socket.send(json.dumps({"id": identifier, "method": method, "params": params}))
        while True:
            message = json.loads(self.socket.recv(timeout=60))
            if message.get("id") == identifier:
                if "error" in message:
                    raise SinkError("CDP call failed")
                return message.get("result", {})

    def evaluate(self, expression: str) -> Any:
        result = self.call("Runtime.evaluate", expression=expression, returnByValue=True)
        return result.get("result", {}).get("value")

    def click(self, x: float, y: float) -> None:
        for kind, buttons in (("mousePressed", 1), ("mouseReleased", 0)):
            self.call(
                "Input.dispatchMouseEvent",
                type=kind,
                x=x,
                y=y,
                button="left",
                clickCount=1,
                buttons=buttons,
            )

    def press(self, key: str) -> None:
        codes = {"Enter": 13, "Tab": 9, "Escape": 27}
        code = codes[key]
        for event in ("keyDown", "keyUp"):
            self.call(
                "Input.dispatchKeyEvent",
                type=event,
                key=key,
                code=key,
                windowsVirtualKeyCode=code,
                nativeVirtualKeyCode=code,
            )


def _state(cdp: Cdp) -> dict:
    raw = cdp.evaluate(STATE_JS)
    if not isinstance(raw, str):
        raise SinkError("page state is unavailable")
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise SinkError("page state is invalid") from exc


def _point(cdp: Cdp, selector: str) -> dict:
    raw = cdp.evaluate(_selector_point_js(selector))
    if raw in {"missing", "hidden"}:
        raise FormError(f"element not found: {selector}")
    try:
        return json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise FormError("element coordinates are invalid") from exc


def _focus_matches(cdp: Cdp, point: dict) -> bool:
    raw = cdp.evaluate(FOCUS_JS)
    try:
        active = json.loads(raw)
    except (TypeError, ValueError):
        return False
    return (
        abs(float(active.get("x", -1)) - point["x"]) <= 2
        and abs(float(active.get("y", -1)) - point["y"]) <= 2
    )


def _fill(cdp: Cdp, selector: str, text: str) -> None:
    point = _point(cdp, selector)
    cdp.click(point["x"], point["y"])
    time.sleep(0.2)
    if not _focus_matches(cdp, point):
        raise FormError(f"focus lost before typing: {selector}")
    cdp.call("Input.insertText", text=text)
    time.sleep(0.2)


def _click(cdp: Cdp, selector: str) -> None:
    point = _point(cdp, selector)
    cdp.click(point["x"], point["y"])
    time.sleep(0.2)


def _wait_visible(cdp: Cdp, selector: str, timeout_ms: int) -> None:
    deadline = time.monotonic() + timeout_ms / 1000
    while time.monotonic() < deadline:
        if cdp.evaluate(_selector_visible_js(selector)) is True:
            return
        time.sleep(POLL_SECONDS)
    raise SinkTimeout(f"element did not appear: {selector}")


def _expect(cdp: Cdp, step: dict) -> None:
    deadline = time.monotonic() + step["timeout_ms"] / 1000
    while time.monotonic() < deadline:
        state = _state(cdp)
        refused = failure_text(state)
        if refused:
            raise AuthRejected(refused)
        if state.get("mfa"):
            raise MfaRequired("verification is required")
        url = str(state.get("url") or "")
        pattern = step.get("url_not")
        contains = step.get("url_contains")
        if pattern is not None and not fnmatch.fnmatch(url, pattern):
            return
        if contains is not None and contains in url:
            return
        time.sleep(POLL_SECONDS)
    raise SinkTimeout("expected page state did not arrive")


def _verify_account(cdp: Cdp, verify: dict, values: dict[str, str | None]) -> str:
    """Read a sessionStorage key after login and compare it to the credential."""
    key = json.dumps(verify["session_storage"])
    raw = cdp.evaluate(
        "(() => { try { return sessionStorage.getItem(" + key + "); }"
        " catch (e) { return null; } })()"
    )
    if not isinstance(raw, str) or not raw:
        raise AccountMismatch("account marker is unavailable after login")
    expected = values.get(verify["equals_ref"])
    if isinstance(expected, str) and expected and raw != expected:
        raise AccountMismatch("logged-in account does not match the credential")
    return raw


def _finish(cdp: Cdp, plan: dict, values: dict[str, str | None], start_url: str = "") -> dict:
    """Confirm the outcome instead of assuming it: refuse, wait for the page, then report."""
    try:
        settle = float(plan.get("settle_ms") or SETTLE_SECONDS * 1000) / 1000
    except (TypeError, ValueError):
        settle = SETTLE_SECONDS
    deadline = time.monotonic() + settle
    state = _state(cdp)
    status, detail = login_outcome(state, start_url)
    while status == "unconfirmed" and time.monotonic() < deadline:
        time.sleep(POLL_SECONDS)
        state = _state(cdp)
        status, detail = login_outcome(state, start_url)
    if status == "rejected":
        raise AuthRejected(detail)
    if status == "mfa":
        raise MfaRequired("verification is required")
    if status == "unconfirmed":
        raise AuthUnconfirmed(detail)
    result: dict = {"status": "logged_in", "url": state.get("url")}
    verify = plan.get("verify")
    if isinstance(verify, dict):
        result["account"] = _verify_account(cdp, verify, values)
    return result


def _run_steps(cdp: Cdp, plan: dict, values: dict[str, str | None]) -> dict:
    start_url = str(_state(cdp).get("url") or "")
    for step in plan["steps"]:
        action = step["action"]
        if action == "fill":
            value = values.get(step["value_ref"])
            if step["value_ref"] == "totp" and not value:
                raise MfaRequired("TOTP is not available for this record")
            if not isinstance(value, str) or not value:
                raise InputError("no value for the fill step")
            _fill(cdp, step["selector"], value)
        elif action == "otp":
            value = values.get("totp")
            if not value:
                raise MfaRequired("TOTP is not available for this record")
            _wait_visible(cdp, step["selector"], step["timeout_ms"])
            _fill(cdp, step["selector"], value)
        elif action == "click":
            _click(cdp, step["selector"])
        elif action == "press":
            cdp.press(step["key"])
        elif action == "wait":
            _wait_visible(cdp, step["selector"], step["timeout_ms"])
        elif action == "expect":
            _expect(cdp, step)
    return _finish(cdp, plan, values, start_url)


def _run_heuristic(cdp: Cdp, values: dict[str, str | None], plan: dict | None = None) -> dict:
    raw = cdp.evaluate(COORDS_JS)
    if not isinstance(raw, str) or raw.startswith("no-"):
        raise FormError(raw if isinstance(raw, str) else "login form is not found")
    form = json.loads(raw)
    start_url = str(form.get("url") or "")
    username = values.get("username") or ""
    password = values.get("password") or ""
    for point, text in ((form["login"], username), (form["pw"], password)):
        cdp.click(point["x"], point["y"])
        time.sleep(0.2)
        if not _focus_matches(cdp, point):
            raise FormError("focus was lost before typing")
        cdp.call("Input.insertText", text=text)
        time.sleep(0.2)
    raw_after = cdp.evaluate(COORDS_JS)
    if not isinstance(raw_after, str) or raw_after.startswith("no-"):
        raise FormError("login form changed before submit")
    submit = json.loads(raw_after)["submit"]
    cdp.click(submit["x"], submit["y"])
    deadline = time.monotonic() + 16
    while time.monotonic() < deadline:
        time.sleep(POLL_SECONDS)
        state = _state(cdp)
        status, detail = login_outcome(state, start_url)
        if status == "rejected":
            raise AuthRejected(detail)
        if status == "mfa":
            raise MfaRequired("verification is required")
        if status == "logged_in":
            result = _finish(cdp, plan or {}, values, start_url)
            result["start_url"] = start_url
            return result
    raise AuthUnconfirmed(login_outcome(_state(cdp), start_url)[1] or "login did not complete")


def run(
    target: dict[str, Any],
    plan: dict[str, Any],
    values: dict[str, str | None],
    *,
    cdp_url: str = DEFAULT_CDP,
    lock_path: Path | None = None,
    page: str | None = None,
) -> dict[str, Any]:
    import websockets.sync.client as ws_client

    lock = None
    if lock_path is not None:
        lock = open(lock_path, "a+", encoding="utf-8")  # noqa: SIM115
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
    try:
        with urllib.request.urlopen(f"{cdp_url}/json/list", timeout=5) as response:
            targets = json.load(response)
        if not isinstance(targets, list):
            raise SinkError("CDP target list is invalid")
        selected = pick_page(targets, target, page)
        if selected is None:
            raise TargetError(f"no browser tab matches {target['host']}:{target['port']}")
        with ws_client.connect(selected["webSocketDebuggerUrl"], max_size=8 * 1024 * 1024) as socket:
            cdp = Cdp(socket)
            cdp.call("Runtime.enable")
            if plan.get("mode") == "profile":
                return _run_steps(cdp, plan, values)
            return _run_heuristic(cdp, values, plan)
    except urllib.error.URLError as exc:
        raise SinkError("CDP endpoint is unavailable") from exc
    finally:
        if lock is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()
