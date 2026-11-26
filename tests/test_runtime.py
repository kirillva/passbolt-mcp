import asyncio
import json
from dataclasses import replace
from urllib.parse import urlsplit
from uuid import uuid4

import pytest

from zai_passbolt.adapter import DomainDecision, PassboltAccessPolicy, PassboltAdapter
from zai_passbolt.errors import SafeToolError
from zai_passbolt.runtime import Runtime, StandaloneHttp
from zai_passbolt.tools import register_tools
from zai_passbolt.transport import ProviderAdmissionDenied, ProviderError, ProviderHttpError

RESOURCE = "11111111-1111-4111-8111-111111111111"
CREATE = dict(
    name="Fixture",
    uri="https://example.com/login",
    username="operator",
    secret_source={"kind": "server_generated"},
    idempotency_key="create-1",
    share_mode="none",
)


class FixtureSinks:
    """Minimal sink surface for tool tests; delivery is stubbed on the adapter."""

    def definition(self, sink_ref):
        return {"kind": "secure_fill", "default_port": 443}

    def target(self, sink_ref, resource_uri):
        host = "example.com"
        scheme = "https"
        if resource_uri:
            parsed = urlsplit(resource_uri)
            host = parsed.hostname or host
            scheme = parsed.scheme or scheme
        return {
            "uri": resource_uri or "https://example.com/login",
            "scheme": scheme,
            "host": host,
            "port": 80 if scheme == "http" else 443,
            "path": "/login",
            "database": None,
        }

    def approval_mode(self, sink_ref):
        return "never"

    def target_from_note(self, sink_ref, note, resource_uri):
        assert "scheme=http" in note
        return {
            "uri": resource_uri,
            "scheme": "http",
            "host": "lab.example",
            "port": 80,
            "path": "/login",
            "database": None,
            "source": "note",
        }

    def requires_job(self, sink_ref):
        return False

    def load_job(self, sink_ref, job_ref):
        raise AssertionError("no job expected in this fixture")

    def archive_job(self, sink_ref, job_ref):
        return None


class FixtureAdapter:
    def __init__(self):
        self.calls = []
        self.fail = None
        self.match = True
        self.wait = None
        self.entered = asyncio.Event()
        self.checkpoint_failure = False
        self.sinks = FixtureSinks()
        # A test can point the fixture record at another site, e.g. a plain-HTTP lab.
        self.record_uri = "https://example.com/login"
        # The write gate keeps its old meaning for the existing refusal test; the
        # "any" policy is what the fork ships by default now.
        self.domain_policy = "allowlist"

    def access_policy(self, label):
        return PassboltAccessPolicy(
            resource_ids=frozenset({RESOURCE}),
            folder_ids=frozenset(),
            group_ids=frozenset(),
            user_ids=frozenset({RESOURCE}),
            domain_hosts=frozenset({"example.com", "other.example"}),
            sink_refs=frozenset({"fill"}),
            allow_create_resource=True,
            allow_create_folder=True,
            resource_scope="all",
            folder_scope="all",
            domain_policy=self.domain_policy,
        )

    async def status(self):
        return {"auth_ready": True, "decrypt_ready": True}

    async def search(self, *args, **kwargs):
        self.calls.append(("search", args))
        return {
            "resources": [{"resource_id": RESOURCE, "uri": self.record_uri}],
            "secret_disclosed": False,
        }

    async def select(self, *args, **kwargs):
        return {
            "resource": {"resource_id": RESOURCE, "uri": self.record_uri, "username": "user"},
            "domain_match": self.match,
            "confirmation_required": not self.match,
        }

    async def resource_note(self, resource_id):
        return "scheme=http\nhost=lab.example\npath=/login"

    def domain_decision(self, resource, target):
        return DomainDecision(
            self.match, "same_host" if self.match else "host_mismatch", "example.com", "example.com"
        )

    async def create_resource(self, **kwargs):
        PassboltAdapter.validate_secret_source(kwargs["secret_source"])
        self.calls.append(("create", kwargs))
        self.entered.set()
        if self.wait:
            await self.wait.wait()
        if self.fail:
            raise self.fail
        if kwargs.get("checkpoint"):
            await kwargs["checkpoint"]({"checkpoint": "resource_created", "resource_id": RESOURCE})
            if self.checkpoint_failure:
                self.checkpoint_failure = False
                raise ProviderError("sharing interrupted")
        return {"resource_id": RESOURCE, "created": True, "secret_disclosed": False}

    async def update_resource(self, **kwargs):
        self.calls.append(("update", kwargs))
        return {"resource_id": RESOURCE, "updated": True}

    async def share_resource(self, **kwargs):
        self.calls.append(("share", kwargs))
        return {"resource_id": RESOURCE, "shared": True}

    async def create_folder(self, **kwargs):
        self.calls.append(("folder", kwargs))
        return {"folder_id": RESOURCE}

    async def use_secret(self, **kwargs):
        self.calls.append(("use", kwargs))
        if self.fail:
            raise self.fail
        return {"delivered_to_sink": True}

    def secret_source_consumed(self, source):
        return True


class Capture:
    def __init__(self):
        self.functions = {}
        self.options = {}

    def tool(self, **options):
        def register(function):
            self.functions[function.__name__] = function
            self.options[function.__name__] = options
            return function

        return register


def harness(config, adapter=None):
    runtime = Runtime(config, "stdio", adapter or FixtureAdapter())
    capture = Capture()
    register_tools(capture, runtime)

    async def call(tool, **args):
        return await runtime.execute(tool, args, lambda: capture.functions[tool](**args))

    return runtime, call


async def approve(runtime, prepared):
    identifier = uuid4() if "approval_id" not in prepared else prepared["approval_id"]
    record = await runtime.store.get_approval(identifier)
    assert record
    assert runtime.store.transition_approval(
        identifier, status="accepted", actor="alice", digest=record.request_hash
    )
    return str(identifier)


async def test_create_replay_restart_hash_ownership_and_no_secret_state(config):
    adapter = FixtureAdapter()
    runtime, call = harness(config, adapter)
    first = await call("passbolt_create_resource", **CREATE)
    assert first["created"] and not first["idempotent"]
    runtime, call = harness(config, adapter)
    assert (await call("passbolt_create_resource", **CREATE))["idempotent"]
    with pytest.raises(SafeToolError):
        await call("passbolt_create_resource", **{**CREATE, "name": "changed"})
    assert len(adapter.calls) == 1
    _, bob = harness(replace(config, principal_id="bob"), adapter)
    assert not (await bob("passbolt_create_resource", **CREATE))["idempotent"]
    raw = config.state_path.read_bytes()
    assert b"Fixture" not in raw and b"server_generated" not in raw


@pytest.mark.parametrize("error", [ProviderError("unknown"), ProviderHttpError(503)])
async def test_unknown_outcome_blocks_same_and_new_keys_after_restart(config, error):
    adapter = FixtureAdapter()
    adapter.fail = error
    _, call = harness(config, adapter)
    with pytest.raises(SafeToolError):
        await call("passbolt_create_resource", **CREATE)
    _, call = harness(config, adapter)
    for key in ["create-1", "create-2"]:
        with pytest.raises(SafeToolError):
            await call("passbolt_create_resource", **{**CREATE, "idempotency_key": key})
    assert len(adapter.calls) == 1


async def test_definitive_failure_requires_new_key(config):
    adapter = FixtureAdapter()
    adapter.fail = ProviderHttpError(400)
    runtime, call = harness(config, adapter)
    with pytest.raises(SafeToolError):
        await call("passbolt_create_resource", **CREATE)
    record = await runtime.store.provider_write_lookup("alice", "passbolt", "create-1")
    assert record["status"] == "failed"
    adapter.fail = None
    with pytest.raises(SafeToolError):
        await call("passbolt_create_resource", **CREATE)
    assert (await call("passbolt_create_resource", **{**CREATE, "idempotency_key": "corrected"}))["created"]


async def test_approval_exact_actor_hash_single_use_and_update(config):
    adapter = FixtureAdapter()
    runtime, call = harness(config, adapter)
    args = dict(
        resource_id=RESOURCE, fields={"name": "changed"}, expected_modified="v1", idempotency_key="u1"
    )
    prepared = await call("passbolt_update_resource", **args)
    assert prepared["confirmation_required"] and not adapter.calls
    record = await runtime.store.get_approval(prepared["approval_id"])
    with pytest.raises(PermissionError):
        runtime.store.transition_approval(
            record.approval_id, status="accepted", actor="bob", digest=record.request_hash
        )
    with pytest.raises(PermissionError):
        runtime.store.transition_approval(
            record.approval_id, status="accepted", actor="alice", digest="wrong"
        )
    approval = await approve(runtime, prepared)
    assert (await call("passbolt_update_resource", **args, approval_id=approval))["updated"]
    assert not await runtime.store.consume_approval(approval)
    with pytest.raises(SafeToolError):
        await call("passbolt_update_resource", **{**args, "idempotency_key": "u2"}, approval_id=approval)
    assert len(adapter.calls) == 1


async def test_checkpoint_resumes_share_without_fresh_create(config):
    adapter = FixtureAdapter()
    adapter.checkpoint_failure = True
    runtime, call = harness(config, adapter)
    args = {**CREATE, "share_mode": "explicit", "share_with_users": [RESOURCE]}
    prepared = await call("passbolt_create_resource", **args)
    approval = await approve(runtime, prepared)
    with pytest.raises(SafeToolError):
        await call("passbolt_create_resource", **args, approval_id=approval)
    record = await runtime.store.provider_write_lookup("alice", "passbolt", "create-1")
    assert record["result"]["resource_id"] == RESOURCE and record["result"]["state"] == "resume_ready"
    _, call = harness(config, adapter)
    result = await call("passbolt_create_resource", **args, approval_id=approval)
    assert result["idempotent"]
    assert adapter.calls[0][1]["resume_resource_id"] is None
    assert adapter.calls[1][1]["resume_resource_id"] == RESOURCE


async def test_selection_is_actor_bound_single_use_and_target_comes_from_record(config):
    adapter = FixtureAdapter()
    _, call = harness(config, adapter)
    chosen = await call("passbolt_select", target_url="https://example.com/login")
    selection = chosen["selection_id"]
    _, bob = harness(replace(config, principal_id="bob"), adapter)
    with pytest.raises(SafeToolError):
        await bob("passbolt_use_secret", selection_id=selection, sink_ref="fill")
    # A caller-supplied target_url is ignored: the record URI is the target.
    _, call = harness(config, adapter)
    assert await call(
        "passbolt_use_secret",
        selection_id=selection,
        sink_ref="fill",
        target_url="https://other.example",
    ) == {"delivered_to_sink": True}
    [(kind, kwargs)] = adapter.calls
    assert kind == "use" and kwargs["resource_uri"] == "https://example.com/login"
    assert kwargs["target"]["host"] == "example.com"
    with pytest.raises(SafeToolError):
        await call("passbolt_use_secret", selection_id=selection, sink_ref="fill")


async def test_record_uri_is_used_without_domain_approval(config):
    adapter = FixtureAdapter()
    adapter.match = False
    _, call = harness(config, adapter)
    chosen = await call("passbolt_select", target_url="https://other.example/login")
    assert chosen["confirmation_required"] is False
    result = await call("passbolt_use_secret", selection_id=chosen["selection_id"], sink_ref="fill")
    assert result == {"delivered_to_sink": True}
    assert adapter.calls[0][1]["resource_uri"] == "https://example.com/login"


async def test_plain_http_delivery_is_not_blocked_by_the_advisory_list(config):
    """The vault is the allowlist; a plain-HTTP record on any host is delivered."""
    adapter = FixtureAdapter()
    adapter.record_uri = "http://lab.example/login"
    _, call = harness(config, adapter)
    chosen = await call("passbolt_select", target_url="http://lab.example/login")
    result = await call("passbolt_use_secret", selection_id=chosen["selection_id"], sink_ref="fill")
    assert result == {"delivered_to_sink": True}
    [(kind, kwargs)] = adapter.calls
    assert kind == "use" and kwargs["target"]["scheme"] == "http"


async def test_plain_http_record_on_an_allowlisted_host_is_delivered(config):
    adapter = FixtureAdapter()
    adapter.record_uri = "http://example.com/login"
    _, call = harness(config, adapter)
    chosen = await call("passbolt_select", target_url="http://example.com/login")
    result = await call("passbolt_use_secret", selection_id=chosen["selection_id"], sink_ref="fill")
    assert result == {"delivered_to_sink": True}
    [(kind, kwargs)] = adapter.calls
    assert kind == "use"
    assert kwargs["target"]["scheme"] == "http" and kwargs["target"]["port"] == 80


async def test_custom_record_resolves_its_target_from_the_note(config):
    """custom:// keeps the address in the note; the sink still receives a plain target."""
    adapter = FixtureAdapter()
    adapter.record_uri = "custom://lab"
    _, call = harness(config, adapter)
    chosen = await call("passbolt_select", query="lab")
    assert chosen["resource"]["uri"] == "custom://lab"
    result = await call("passbolt_use_secret", selection_id=chosen["selection_id"], sink_ref="fill")
    assert result == {"delivered_to_sink": True}
    [(kind, kwargs)] = adapter.calls
    assert kind == "use"
    assert kwargs["target"]["source"] == "note"
    assert (kwargs["target"]["host"], kwargs["target"]["port"]) == ("lab.example", 80)


async def test_auto_approval_applies_the_write_and_logs_the_change(config):
    """The operator's standing policy applies the write in one call; the change is logged."""
    adapter = FixtureAdapter()
    adapter.domain_policy = "any"
    _, call = harness(replace(config, passbolt_write_approval="auto"), adapter)
    result = await call(
        "passbolt_update_resource",
        resource_id=RESOURCE,
        fields={"uri": "postgresql://db.example:5432/app", "description": "top secret note"},
        expected_modified="v1",
        idempotency_key="u-auto",
    )
    assert result["updated"] is True and result["approval"] == "auto"
    [(kind, kwargs)] = adapter.calls
    assert kind == "update" and kwargs["fields"]["uri"].startswith("postgresql://")

    log = config.state_path.parent / "data-changes.jsonl"
    raw = log.read_text(encoding="utf-8")
    [entry] = [json.loads(line) for line in raw.splitlines()]
    assert entry["operation"] == "update_resource"
    assert entry["approval"] == "auto" and entry["actor"] == "alice"
    assert entry["changes"]["fields"]["uri"] == "postgresql://db.example:5432/app"
    assert entry["changes"]["fields"]["description"] == {"chars": 15}
    assert entry["result"]["updated"] is True
    assert "top secret note" not in raw and "secret_source" not in entry["changes"]


def test_write_approval_defaults_to_operator_and_is_validated(config):
    assert config.passbolt_write_approval == "operator"
    with pytest.raises(ValueError, match="PASSBOLT_WRITE_APPROVAL"):
        replace(config, passbolt_write_approval="sometimes")


async def test_a_failed_tool_call_lands_in_the_local_error_log(config, monkeypatch):
    """The operator reads this file to fix the instructions; it must be there and be safe."""
    monkeypatch.delenv("PASSBOLT_TOOL_LOG", raising=False)
    adapter = FixtureAdapter()
    _, call = harness(config, adapter)
    with pytest.raises(SafeToolError):
        await call("passbolt_select", target_url="ftp://example.com/login")

    log = config.state_path.parent / "tool-errors.jsonl"
    entries = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [entry["tool"] for entry in entries] == ["passbolt_select"]
    entry = entries[0]
    assert entry["code"] == "validation_failed"
    assert entry["arguments"]["target_url"] == "<scheme>://example.com"
    assert entry["duration_ms"] >= 0 and entry["version"] and entry["execution_id"]


async def test_cancelled_create_leaves_pending_and_conservative_lease(config):
    adapter = FixtureAdapter()
    adapter.wait = asyncio.Event()
    runtime, call = harness(config, adapter)
    task = asyncio.create_task(call("passbolt_create_resource", **CREATE))
    await asyncio.wait_for(adapter.entered.wait(), timeout=5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    record = await runtime.store.provider_write_lookup("alice", "passbolt", "create-1")
    assert record["status"] == "pending"
    with pytest.raises(ProviderAdmissionDenied):
        runtime.store.begin("next", "bob", "passbolt_status", "hash")


async def test_quota_counts_initial_and_retry_and_is_shared_by_actors(config):
    runtime, _ = harness(replace(config, rate_limit=2))
    runtime.state.set(type("Call", (), {"principal_id": "alice"})())
    http = StandaloneHttp(runtime)
    await http._admit_attempt(1)
    await http._admit_attempt(2)
    runtime, _ = harness(replace(config, rate_limit=2, principal_id="bob"))
    runtime.state.set(type("Call", (), {"principal_id": "bob"})())
    with pytest.raises(ProviderAdmissionDenied):
        await StandaloneHttp(runtime)._admit_attempt(1)


def test_custody_change_cannot_reuse_ledger(config):
    harness(config)
    with pytest.raises(ValueError, match="custody changed"):
        harness(replace(config, bindings={"alice": "different"}))


@pytest.mark.parametrize(
    "args",
    [
        dict(rate_limit=11),
        dict(rate_limit=-1),
        dict(max_concurrency=2),
        dict(local_scopes={"admin"}),
    ],
)
def test_policy_cannot_exceed_default_ceiling(config, args):
    with pytest.raises(ValueError):
        replace(config, **args)


async def test_write_use_disabled_and_plaintext_source_rejected(config):
    adapter = FixtureAdapter()
    _, call = harness(replace(config, passbolt_write_enabled=False, passbolt_use_enabled=False), adapter)
    for tool, args in [
        ("passbolt_create_resource", CREATE),
        ("passbolt_use_secret", dict(selection_id=str(uuid4()), sink_ref="fill")),
    ]:
        with pytest.raises(SafeToolError):
            await call(tool, **args)
    assert not adapter.calls
    _, call = harness(config, adapter)
    with pytest.raises(SafeToolError) as error:
        await call(
            "passbolt_create_resource",
            **{**CREATE, "secret_source": {"kind": "plaintext", "value": "do-not-log"}},
        )
    assert "do-not-log" not in str(error.value)
    assert b"do-not-log" not in config.state_path.read_bytes()


@pytest.mark.parametrize(
    "uri",
    [
        "https://evil.example/login",
        "https://example.com.evil.example/login",
        "https://example.com:8443/login",
        "http://example.com/login",
        7,
    ],
)
async def test_update_refuses_off_policy_uri_before_approval_or_adapter(config, uri):
    adapter = FixtureAdapter()
    runtime, call = harness(config, adapter)
    args = dict(
        resource_id=RESOURCE,
        fields={"uri": uri, "secret_source": {"kind": "server_generated"}},
        expected_modified="v1",
        idempotency_key="u-off-policy",
    )
    with pytest.raises(SafeToolError) as error:
        await call("passbolt_update_resource", **args)
    assert "provider_disabled" in str(error.value) and "evil" not in str(error.value)
    # The adapter is never entered: no secret-source read, decryption, encryption or PUT.
    assert adapter.calls == []
    # Nothing was prepared, so no approval can later unlock this request.
    assert await runtime.store.provider_write_lookup("alice", "passbolt", "u-off-policy") is None


@pytest.mark.parametrize("uri", ["https://other.example/login", "https://EXAMPLE.com:443/x", None, ""])
async def test_update_accepts_policy_uri_or_primary_uri_removal(config, uri):
    adapter = FixtureAdapter()
    runtime, call = harness(config, adapter)
    args = dict(
        resource_id=RESOURCE,
        fields={"uri": uri, "secret_source": {"kind": "server_generated"}},
        expected_modified="v1",
        idempotency_key="u-on-policy",
    )
    prepared = await call("passbolt_update_resource", **args)
    assert prepared["confirmation_required"] and not adapter.calls
    approval = await approve(runtime, prepared)
    assert (await call("passbolt_update_resource", **args, approval_id=approval))["updated"]
    [(kind, kwargs)] = adapter.calls
    assert kind == "update" and kwargs["fields"]["uri"] == uri


async def test_update_accepts_a_new_site_when_domain_policy_is_any(config):
    """Default policy: the vault is the allowlist, so a new site needs no settings edit."""
    adapter = FixtureAdapter()
    adapter.domain_policy = "any"
    runtime, call = harness(config, adapter)
    args = dict(
        resource_id=RESOURCE,
        fields={"uri": "https://new.example/login", "secret_source": {"kind": "server_generated"}},
        expected_modified="v1",
        idempotency_key="u-any-site",
    )
    prepared = await call("passbolt_update_resource", **args)
    assert prepared["confirmation_required"] and not adapter.calls
    approval = await approve(runtime, prepared)
    assert (await call("passbolt_update_resource", **args, approval_id=approval))["updated"]
    [(kind, kwargs)] = adapter.calls
    assert kind == "update" and kwargs["fields"]["uri"] == "https://new.example/login"


async def test_share_elicitation_only_for_valid_matching_approval(config, monkeypatch):
    from zai_passbolt import tools as tools_mod

    asked = []

    async def fake_confirm(message, mode="auto"):
        asked.append(message)
        return "accepted"

    monkeypatch.setattr(tools_mod, "confirm_share", fake_confirm)
    adapter = FixtureAdapter()
    runtime, call = harness(config, adapter)
    args = {"resource_id": RESOURCE, "permission": "read", "idempotency_key": "s1", "users": [RESOURCE]}
    prepared = await call("passbolt_share_resource", **args)
    assert not asked and not adapter.calls
    # Prepared but not accepted, or a random id: no prompt, and the write is refused.
    for bogus in (prepared["approval_id"], str(uuid4()), "not-a-uuid"):
        with pytest.raises(SafeToolError):
            await call("passbolt_share_resource", **args, approval_id=bogus)
    assert not asked and not adapter.calls
    approval = await approve(runtime, prepared)
    # Accepted approval but a different request (other permission): no prompt, refused.
    with pytest.raises(SafeToolError):
        await call("passbolt_share_resource", **{**args, "permission": "update"}, approval_id=approval)
    assert not asked
    result = await call("passbolt_share_resource", **args, approval_id=approval)
    assert result["shared"] and result["elicitation"] == "accepted" and len(asked) == 1


async def test_move_resource_is_approval_gated(config):
    adapter = FixtureAdapter()
    moved = []

    async def move_resource(resource_id, folder_id):
        moved.append((resource_id, folder_id))
        return {"resource_id": resource_id, "folder_id": folder_id, "moved": True}

    adapter.move_resource = move_resource
    runtime, call = harness(config, adapter)
    args = {"resource_id": RESOURCE, "idempotency_key": "m1"}
    prepared = await call("passbolt_move_resource", **args)
    assert prepared["confirmation_required"] and not moved
    approval = await approve(runtime, prepared)
    assert (await call("passbolt_move_resource", **args, approval_id=approval))["moved"]
    assert moved == [(RESOURCE, None)]


async def test_move_and_directory_normalize_resource_uuid(config):
    adapter = FixtureAdapter()
    moved = []
    perms = []

    async def move_resource(resource_id, folder_id):
        moved.append(resource_id)
        return {"resource_id": resource_id, "folder_id": folder_id, "moved": True}

    async def resource_permissions(resource_id):
        perms.append(resource_id)
        return {"resource_id": resource_id, "permissions": []}

    adapter.move_resource = move_resource
    adapter.resource_permissions = resource_permissions
    runtime, call = harness(config, adapter)
    args = {"resource_id": RESOURCE.upper(), "idempotency_key": "m2"}
    prepared = await call("passbolt_move_resource", **args)
    approval = await approve(runtime, prepared)
    assert (await call("passbolt_move_resource", **args, approval_id=approval))["moved"]
    assert moved == [RESOURCE]
    await call("passbolt_directory", resource_id=RESOURCE.upper())
    assert perms == [RESOURCE]
    with pytest.raises(SafeToolError):
        await call("passbolt_directory", resource_id="not-a-uuid")


async def test_move_folder_and_unshare_are_approval_gated(config):
    adapter = FixtureAdapter()
    done = []

    async def move_folder(folder_id, parent_id):
        done.append(("move", folder_id, parent_id))
        return {"folder_id": folder_id, "parent_id": parent_id, "moved": True}

    async def unshare(kind, target_id, aro_ids):
        done.append(("unshare", kind, target_id, tuple(aro_ids)))
        return {"resource_id": target_id, "removed": 1, "owners_kept": 0, "unshared": True}

    adapter.move_folder = move_folder
    adapter.unshare = unshare
    runtime, call = harness(config, adapter)
    margs = {"folder_id": RESOURCE.upper(), "idempotency_key": "f1"}
    prepared = await call("passbolt_move_folder", **margs)
    assert prepared["confirmation_required"] and not done
    approval = await approve(runtime, prepared)
    assert (await call("passbolt_move_folder", **margs, approval_id=approval))["moved"]
    uargs = {"kind": "resource", "target_id": RESOURCE, "aro_ids": [RESOURCE], "idempotency_key": "u1"}
    prepared = await call("passbolt_unshare", **uargs)
    assert prepared["confirmation_required"]
    approval = await approve(runtime, prepared)
    with pytest.raises(SafeToolError):  # approval is bound to the exact request
        await call("passbolt_unshare", **{**uargs, "kind": "folder"}, approval_id=approval)
    assert (await call("passbolt_unshare", **uargs, approval_id=approval))["unshared"]
    assert done == [("move", RESOURCE, None), ("unshare", "resource", RESOURCE, (RESOURCE,))]
    with pytest.raises(SafeToolError):
        await call(
            "passbolt_unshare", kind="resource", target_id=RESOURCE, aro_ids=["x"], idempotency_key="u2"
        )


async def test_adapter_move_folder_and_unshare_follow_api_v5(monkeypatch):
    adapter = PassboltAdapter.__new__(PassboltAdapter)
    sent = []
    owner, reader = str(uuid4()), str(uuid4())

    async def fake_request(method, path, payload=None, params=None, **_):
        sent.append((method, path, payload))
        if path.startswith("/permissions/resource/"):
            return {
                "body": [
                    {"id": "p-owner", "aro_foreign_key": owner, "type": 15},
                    {"id": "p-read", "aro_foreign_key": reader, "type": 1},
                ]
            }
        return {"body": {}}

    adapter._request = fake_request
    out = await adapter.move_folder(RESOURCE, None)
    assert sent[-1] == ("PUT", f"/move/folder/{RESOURCE}.json", {"folder_parent_id": None}) and out["moved"]
    with pytest.raises(ValueError):
        await adapter.move_folder(RESOURCE, RESOURCE)
    sent.clear()
    out = await adapter.unshare("resource", RESOURCE, [owner, reader])
    assert out == {"resource_id": RESOURCE, "removed": 1, "owners_kept": 1, "unshared": True}
    assert sent[1] == (
        "POST",
        f"/share/simulate/resource/{RESOURCE}.json",
        {"permissions": [{"id": "p-read", "delete": True}]},
    )
    # Re-read right before the PUT (owner-promotion guard), then the PUT itself.
    assert sent[2][:2] == ("GET", f"/permissions/resource/{RESOURCE}.json")
    assert sent[3] == (
        "PUT",
        f"/share/resource/{RESOURCE}.json",
        {"permissions": [{"id": "p-read", "delete": True}], "secrets": []},
    )


async def test_directory_tool_scopes_listing_to_binding_share_targets(config):
    adapter = FixtureAdapter()
    asked = []

    async def list_directory(*, group_ids, user_ids):
        asked.append((group_ids, user_ids))
        return {"groups": [], "users": []}

    adapter.list_directory = list_directory
    _runtime, call = harness(config, adapter)
    await call("passbolt_directory")
    policy = adapter.access_policy("default")
    assert asked == [(policy.group_ids, policy.user_ids)]


async def test_organize_failures_are_audited(config):
    import json
    import sqlite3

    adapter = FixtureAdapter()

    async def broken(*_args):
        raise ProviderError("vault down")

    adapter.move_folder = broken
    adapter.unshare = broken
    runtime, call = harness(config, adapter)
    for tool, args in (
        ("passbolt_move_folder", {"folder_id": RESOURCE, "idempotency_key": "fail-f"}),
        (
            "passbolt_unshare",
            {"kind": "resource", "target_id": RESOURCE, "aro_ids": [RESOURCE], "idempotency_key": "fail-u"},
        ),
    ):
        approval = await approve(runtime, await call(tool, **args))
        with pytest.raises(SafeToolError):
            await call(tool, **args, approval_id=approval)
    with sqlite3.connect(config.state_path) as db:
        rows = [json.loads(data) for (data,) in db.execute("SELECT data FROM passbolt_audit")]
    errors = {(row["action"], row["outcome"]) for row in rows if row["outcome"] == "error"}
    assert errors == {("move_folder", "error"), ("unshare", "error")}


async def test_checkpoint_share_resume_asks_elicitation_again(config, monkeypatch):
    """A create-with-share resume executes the share: it must be confirmed again, approval or not."""
    from zai_passbolt import tools as tools_mod

    asked, answers = [], ["accepted", PermissionError("declined"), "accepted"]

    async def fake_confirm(message, mode="auto"):
        asked.append(message)
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(tools_mod, "confirm_share", fake_confirm)
    adapter = FixtureAdapter()
    adapter.checkpoint_failure = True
    runtime, call = harness(config, adapter)
    args = {**CREATE, "share_mode": "explicit", "share_with_users": [RESOURCE]}
    approval = await approve(runtime, await call("passbolt_create_resource", **args))
    with pytest.raises(SafeToolError):
        await call("passbolt_create_resource", **args, approval_id=approval)
    assert len(asked) == 1 and len(adapter.calls) == 1
    # Resume without approval_id (the approval was consumed): declined prompt, nothing resumes.
    with pytest.raises(SafeToolError):
        await call("passbolt_create_resource", **args)
    assert len(asked) == 2 and len(adapter.calls) == 1
    record = await runtime.store.provider_write_lookup("alice", "passbolt", "create-1")
    assert record["result"]["state"] == "resume_ready"
    result = await call("passbolt_create_resource", **args)
    assert result["idempotent"] and len(asked) == 3 and len(adapter.calls) == 2
    # A completed result is replayed without a prompt and without touching Passbolt.
    assert (await call("passbolt_create_resource", **args))["idempotent"]
    assert len(asked) == 3 and len(adapter.calls) == 2


async def test_adapter_unshare_refuses_when_selected_permission_became_owner(monkeypatch):
    from zai_passbolt.transport import ProviderPreconditionFailed

    adapter = PassboltAdapter.__new__(PassboltAdapter)
    sent, reads = [], []
    reader = str(uuid4())

    async def fake_request(method, path, payload=None, params=None, **_):
        sent.append((method, path, payload))
        if path.startswith("/permissions/resource/"):
            reads.append(path)
            # Another owner promotes the selected reader between the first read and the apply.
            kind = 1 if len(reads) == 1 else 15
            return {"body": [{"id": "p-read", "aro_foreign_key": reader, "type": kind}]}
        return {"body": {}}

    adapter._request = fake_request
    with pytest.raises(ProviderPreconditionFailed):
        await adapter.unshare("resource", RESOURCE, [reader])
    assert len(reads) == 2 and not [item for item in sent if item[0] == "PUT"]


async def test_unshare_precondition_failure_is_definitive_not_pending(config):
    from zai_passbolt.transport import ProviderPreconditionFailed

    adapter = FixtureAdapter()

    async def unshare(kind, target_id, aro_ids):
        raise ProviderPreconditionFailed("permissions changed")

    adapter.unshare = unshare
    runtime, call = harness(config, adapter)
    uargs = dict(kind="resource", target_id=RESOURCE, aro_ids=[RESOURCE], idempotency_key="u-race")
    approval = await approve(runtime, await call("passbolt_unshare", **uargs))
    with pytest.raises(SafeToolError) as caught:
        await call("passbolt_unshare", **uargs, approval_id=approval)
    assert caught.value.error_code == "provider_precondition_failed"
    record = await runtime.store.provider_write_lookup("alice", "passbolt", "u-race")
    assert record["status"] == "failed"
    # Nothing was changed in Passbolt, so other writes are not blocked as an unknown outcome.
    assert (await call("passbolt_create_resource", **{**CREATE, "idempotency_key": "after"}))["created"]
