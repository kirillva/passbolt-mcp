import asyncio
import time
from dataclasses import replace

import pytest
from test_runtime import RESOURCE, Capture, FixtureAdapter, approve, harness

from zai_passbolt.errors import SafeToolError
from zai_passbolt.runtime import (
    READ_ONLY_VAULT_TOOLS,
    WRITE_TOOLS,
    CallState,
    Runtime,
    StandaloneHttp,
)
from zai_passbolt.tools import register_tools
from zai_passbolt.transport import ProviderAdmissionDenied


async def test_proven_pre_dispatch_quota_denial_is_retryable_with_new_approval_and_key(config):
    adapter = FixtureAdapter()
    runtime, call = harness(config, adapter)
    sends = []

    async def update(**kwargs):
        await StandaloneHttp(runtime)._admit_attempt(1)
        sends.append(kwargs)
        return {"updated": True, "resource_id": RESOURCE}

    adapter.update_resource = update
    args = dict(resource_id=RESOURCE, fields={"name": "new"}, expected_modified="v1", idempotency_key="u1")
    prepared = await call("passbolt_update_resource", **args)
    approval = await approve(runtime, prepared)
    for _ in range(config.rate_limit):
        runtime.store.admit("alice")
    with pytest.raises(SafeToolError):
        await call("passbolt_update_resource", **args, approval_id=approval)
    record = await runtime.store.provider_write_lookup("alice", "passbolt", "u1")
    assert record["status"] == "failed"
    assert sends == []
    with runtime.store.connect() as db:
        db.execute("UPDATE attempts SET started=0")
    args["idempotency_key"] = "u2"
    prepared = await call("passbolt_update_resource", **args)
    approval = await approve(runtime, prepared)
    assert (await call("passbolt_update_resource", **args, approval_id=approval))["updated"]
    assert len(sends) == 1


@pytest.mark.parametrize("child_task", [False, True])
async def test_later_admission_denial_remains_pending_including_child_task_dispatch(config, child_task):
    adapter = FixtureAdapter()
    runtime, call = harness(replace(config, rate_limit=1), adapter)

    async def update(**kwargs):
        http = StandaloneHttp(runtime)
        if child_task:
            await asyncio.create_task(http._admit_attempt(1))
        else:
            await http._admit_attempt(1)
        await http._admit_attempt(2)
        raise AssertionError("second dispatch must be denied")

    adapter.update_resource = update
    args = dict(resource_id=RESOURCE, fields={"name": "new"}, expected_modified="v1", idempotency_key="u1")
    prepared = await call("passbolt_update_resource", **args)
    approval = await approve(runtime, prepared)
    with pytest.raises(SafeToolError):
        await call("passbolt_update_resource", **args, approval_id=approval)
    record = await runtime.store.provider_write_lookup("alice", "passbolt", "u1")
    assert record["status"] == "pending"


async def _search_that_admits(runtime, adapter):
    """Search stub that dispatches through the same HTTP admission boundary as the real adapter."""

    async def search(*args, **kwargs):
        await StandaloneHttp(runtime)._admit_attempt(1)
        return {"resources": [{"resource_id": RESOURCE}], "secret_disclosed": False}

    adapter.search = search


async def test_operator_can_lift_the_quota_for_metadata_reads(config):
    adapter = FixtureAdapter()
    runtime, call = harness(replace(config, rate_limit_exempt_read_only=True, rate_limit=2), adapter)
    await _search_that_admits(runtime, adapter)
    runtime.store.admit("alice")
    runtime.store.admit("alice")
    # The 60s window is spent: metadata reads continue, vault writes still wait.
    assert (await call("passbolt_search", query="mail"))["resources"]
    assert (await call("passbolt_search", query="mail"))["resources"]
    token = runtime.state.set(CallState("exhausted-quota", "alice", "passbolt_update_resource"))
    try:
        with pytest.raises(ProviderAdmissionDenied):
            await StandaloneHttp(runtime)._admit_attempt(1)
    finally:
        runtime.state.reset(token)
    with runtime.store.connect() as db:
        counted = db.execute(
            "SELECT COUNT(*) FROM attempts WHERE account=? AND started>?", ("default", time.time() - 60)
        ).fetchone()[0]
    assert counted == 2


async def test_default_policy_still_limits_metadata_reads(config):
    adapter = FixtureAdapter()
    runtime, call = harness(replace(config, rate_limit=1), adapter)
    await _search_that_admits(runtime, adapter)
    assert (await call("passbolt_search", query="mail"))["resources"]
    with pytest.raises(SafeToolError):
        await call("passbolt_search", query="mail")


async def test_exempt_metadata_reads_still_wait_for_a_provider_cooldown(config):
    adapter = FixtureAdapter()
    runtime, call = harness(replace(config, rate_limit_exempt_read_only=True), adapter)
    await _search_that_admits(runtime, adapter)
    runtime.store.cooldown("alice", 60)
    with pytest.raises(SafeToolError):
        await call("passbolt_search", query="mail")


def test_quota_exempt_tools_are_declared_read_only(config):
    runtime = Runtime(config, "stdio", FixtureAdapter())
    capture = Capture()
    register_tools(capture, runtime)
    read_only = {
        name
        for name, options in capture.options.items()
        if (options.get("annotations") or {}).get("readOnlyHint")
    }
    assert read_only >= READ_ONLY_VAULT_TOOLS
    assert not READ_ONLY_VAULT_TOOLS & WRITE_TOOLS


async def test_arbitrary_factory_admission_error_cannot_claim_no_dispatch(config):
    adapter = FixtureAdapter()
    runtime, call = harness(config, adapter)

    async def update(**kwargs):
        raise ProviderAdmissionDenied("not minted at the local HTTP boundary")

    adapter.update_resource = update
    args = dict(resource_id=RESOURCE, fields={"name": "new"}, expected_modified="v1", idempotency_key="u1")
    prepared = await call("passbolt_update_resource", **args)
    approval = await approve(runtime, prepared)
    with pytest.raises(SafeToolError):
        await call("passbolt_update_resource", **args, approval_id=approval)
    record = await runtime.store.provider_write_lookup("alice", "passbolt", "u1")
    assert record["status"] == "pending"
