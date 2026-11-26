from __future__ import annotations

import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SINKS = ROOT / "examples" / "sinks"
sys.path.insert(0, str(SINKS))

from passbolt_sinkkit.cli import DEFAULT_DATABASES, PROTOCOLS  # noqa: E402
from passbolt_sinkkit.errors import (  # noqa: E402
    AuthRejected,
    InputError,
    TargetError,
)
from passbolt_sinkkit.executors import android as android_exec  # noqa: E402
from passbolt_sinkkit.guards import android as android_guard  # noqa: E402

PACKAGE = "ru.itserv.skr"
TARGET = {"host": PACKAGE, "port": 5037, "path": "/SecurityActivity", "scheme": "android"}
LOGIN_ID = f"{PACKAGE}:id/security_login"
PASS_ID = f"{PACKAGE}:id/security_pass"
OK_ID = f"{PACKAGE}:id/security_ok"


def ui(children: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<hierarchy rotation="0"><node class="android.widget.FrameLayout">{children}</node></hierarchy>'
    )


def field(resource_id: str, text: str, *, password: bool = False) -> str:
    return (
        f'<node class="android.widget.EditText" resource-id="{resource_id}" text="{text}" '
        f'content-desc="" password="{str(password).lower()}" clickable="true" enabled="true" '
        'bounds="[0,0][10,10]" />'
    )


def button(resource_id: str, description: str = "Ок") -> str:
    return (
        f'<node class="android.widget.ImageButton" resource-id="{resource_id}" text="" '
        f'content-desc="{description}" password="false" clickable="true" enabled="true" '
        'bounds="[0,0][10,10]" />'
    )


def text_node(value: str) -> str:
    return (
        f'<node class="android.widget.TextView" resource-id="" text="{value}" content-desc="" '
        'password="false" clickable="false" enabled="true" bounds="[0,0][10,10]" />'
    )


LOGIN_SCREEN = ui(field(LOGIN_ID, "Логин") + field(PASS_ID, "Пароль", password=True) + button(OK_ID))
HOME_SCREEN = ui('<node class="android.widget.TextView" resource-id="home" text="Главная" enabled="true" />')
REFUSED_SCREEN = ui(
    field(LOGIN_ID, "Логин")
    + field(PASS_ID, "Пароль", password=True)
    + button(OK_ID)
    + text_node("Неверный логин или пароль")
)


class FakeObject:
    _ALIASES = {"resourceId": "resource_id", "className": "class_name"}

    def __init__(self, device: FakeDevice, selector: dict[str, Any]) -> None:
        self.device = device
        self.selector = {self._ALIASES.get(key, key): value for key, value in selector.items()}
        self._typed = ""

    def _node(self):
        root = ElementTree.fromstring(self.device.screens[0])
        for node in root.iter("node"):
            pairs = {
                "text": "text",
                "resource_id": "resource-id",
                "class_name": "class",
                "description": "content-desc",
            }
            if all(node.get(pairs[key]) == value for key, value in self.selector.items()):
                return node
        return None

    def wait(self, timeout: float) -> bool:
        return self._node() is not None

    @property
    def exists(self) -> bool:
        return self._node() is not None

    def set_text(self, value: str) -> None:
        self.device.typed.append(("set_text", self.selector, value))
        self._typed = value

    def get_text(self) -> str:
        if getattr(self.device, "mask_get_text", False):
            return "•" * len(self._typed)
        return self._typed

    def click(self) -> None:
        self.device.clicks.append(self.selector)
        if self.device.on_click is not None:
            self.device.on_click(self.device)

    def wait_gone(self, timeout: float) -> bool:
        return not self.exists


class FakeDevice:
    def __init__(self, screens: list[str], *, package: str = PACKAGE, on_click=None) -> None:
        self.screens, self.package, self.on_click = screens, package, on_click
        self.typed: list[tuple[str, dict[str, Any], str]] = []
        self.clicks: list[dict[str, Any]] = []
        self.pressed: list[str] = []
        self.mask_get_text = False

    def app_current(self) -> dict[str, Any]:
        return {"package": self.package, "activity": ".SecurityActivity"}

    def dump_hierarchy(self, compressed: bool = False) -> str:
        return self.screens[0]

    def __call__(self, **selector: Any) -> FakeObject:
        return FakeObject(self, selector)

    def press(self, key: str) -> None:
        self.pressed.append(key)

    def click(self, x: int, y: int) -> None:  # coordinate fallback in the heuristic
        self.clicks.append({"point": (x, y)})


def _fake_u2(monkeypatch: pytest.MonkeyPatch, device: FakeDevice) -> None:
    module = type(sys)("uiautomator2")
    module.connect = lambda serial=None: device  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "uiautomator2", module)


PROFILE_PLAN = {
    "mode": "profile",
    "package": PACKAGE,
    "activity": "SecurityActivity",
    "timeout_ms": 2_000,
    "steps": [
        {
            "action": "fill",
            "selector": {"resource_id": LOGIN_ID},
            "value_ref": "username",
            "timeout_ms": 1_000,
        },
        {
            "action": "fill",
            "selector": {"resource_id": PASS_ID},
            "value_ref": "password",
            "timeout_ms": 1_000,
        },
        {"action": "click", "selector": {"resource_id": OK_ID}, "timeout_ms": 1_000},
    ],
}


def test_profile_plan_matches_package_and_activity() -> None:
    document = {
        "profiles": {
            "skr": {
                "match": {"package": PACKAGE, "activity": "SecurityActivity"},
                "steps": [
                    {
                        "action": "fill",
                        "selector": {"resource_id": LOGIN_ID},
                        "value_ref": "username",
                    }
                ],
                "verify": {"present": {"resource_id": "home"}, "timeout_ms": 3_000},
            }
        }
    }
    plan = android_guard.build_plan(document, TARGET)
    assert plan["mode"] == "profile" and plan["package"] == PACKAGE
    assert plan["verify"]["present"] == {"resource_id": "home"}


def test_profile_is_optional_and_falls_back_to_the_heuristic() -> None:
    plan = android_guard.build_plan({"profiles": {}}, TARGET)
    assert plan["mode"] == "heuristic" and plan["package"] == PACKAGE
    with pytest.raises(InputError):
        android_guard.build_plan({"profiles": {}}, {**TARGET, "host": "Not A Package"})


@pytest.mark.parametrize(
    "step",
    [
        {"action": "shell", "selector": {"text": "x"}},
        {"action": "fill", "selector": {"text": "x", "resource_id": "y"}, "value_ref": "username"},
        {"action": "fill", "selector": {"text": "x"}, "value_ref": "totp"},
        {"action": "press", "key": "F12"},
        {"action": "click", "selector": {"xpath": "../../etc"}},
    ],
)
def test_profile_steps_reject_unsafe_or_ambiguous_input(step: dict[str, Any]) -> None:
    with pytest.raises(InputError):
        android_guard.validate_step(step)


def test_profile_verify_needs_exactly_one_direction() -> None:
    assert android_guard.validate_verify({"present": {"text": "Главная"}})["present"] == {"text": "Главная"}
    with pytest.raises(InputError):
        android_guard.validate_verify({"present": {"text": "a"}, "absent": {"text": "b"}})
    with pytest.raises(InputError):
        android_guard.validate_verify({})


def test_profile_flow_logs_in_and_types_through_the_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    device = FakeDevice([LOGIN_SCREEN], on_click=lambda dev: dev.screens.__setitem__(0, HOME_SCREEN))
    _fake_u2(monkeypatch, device)

    result = android_exec.run(TARGET, "operator", "s3cret", PROFILE_PLAN)

    assert result == {"status": "logged_in", "package": PACKAGE, "activity": ".SecurityActivity"}
    assert device.typed == [
        ("set_text", {"resource_id": LOGIN_ID}, "operator"),
        ("set_text", {"resource_id": PASS_ID}, "s3cret"),
    ]
    assert device.clicks == [{"resource_id": OK_ID}]
    assert device.pressed == []  # no shell, no key injection


def test_app_refusal_is_reported_with_the_site_wording(monkeypatch: pytest.MonkeyPatch) -> None:
    device = FakeDevice([LOGIN_SCREEN], on_click=lambda dev: dev.screens.__setitem__(0, REFUSED_SCREEN))
    _fake_u2(monkeypatch, device)

    with pytest.raises(AuthRejected, match="Неверный логин или пароль"):
        android_exec.run(TARGET, "operator", "s3cret", PROFILE_PLAN)


def test_a_still_visible_login_form_is_a_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """No wording needed: if the login fields are still there, the sign-in failed."""
    device = FakeDevice([LOGIN_SCREEN])  # the click changes nothing
    _fake_u2(monkeypatch, device)

    with pytest.raises(AuthRejected, match="login fields are still on screen"):
        android_exec.run(TARGET, "operator", "s3cret", {**PROFILE_PLAN, "timeout_ms": 600})


def test_a_foreign_foreground_app_is_refused_before_typing(monkeypatch: pytest.MonkeyPatch) -> None:
    device = FakeDevice([LOGIN_SCREEN], package="com.android.settings")
    _fake_u2(monkeypatch, device)

    with pytest.raises(TargetError, match="not in the foreground"):
        android_exec.run(TARGET, "operator", "s3cret", PROFILE_PLAN)
    assert device.typed == []


def test_heuristic_fills_the_two_fields_and_presses_the_button(monkeypatch: pytest.MonkeyPatch) -> None:
    form = ui(
        field(LOGIN_ID, "Логин")
        + field(PASS_ID, "Пароль", password=True)
        + button(OK_ID)
    )
    device = FakeDevice([form], on_click=lambda dev: dev.screens.__setitem__(0, HOME_SCREEN))
    _fake_u2(monkeypatch, device)
    plan = android_guard.build_plan({"profiles": {}}, TARGET)

    result = android_exec.run(TARGET, "operator", "s3cret", plan)

    assert result["status"] == "logged_in"
    assert [value for _, _, value in device.typed] == ["operator", "s3cret"]
    assert device.clicks == [{"resource_id": OK_ID}]


def test_the_android_protocol_is_wired_into_the_cli() -> None:
    assert PROTOCOLS["android"] == "android_fill"
    assert DEFAULT_DATABASES["android"] is None


def test_a_masked_password_readback_is_not_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Android answers a password field with dots; that must not fail the fill."""
    device = FakeDevice([LOGIN_SCREEN], on_click=lambda dev: dev.screens.__setitem__(0, HOME_SCREEN))
    device.mask_get_text = True
    _fake_u2(monkeypatch, device)

    result = android_exec.run(TARGET, "operator", "s3cret", PROFILE_PLAN)

    assert result["status"] == "logged_in"
