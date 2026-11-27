"""Local key and policy readiness; no vault or destination requests."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import stat
from pathlib import Path
from uuid import UUID

from zai_passbolt.config import ServiceConfig
from zai_passbolt.https_probe import validate_probe
from zai_passbolt.onboarding import load_config
from zai_passbolt.profiles import Profiles

_SINK_REFERENCE_FILES = ("known_hosts", "profiles_file", "sslrootcert")


def _posix_mode_gate() -> bool:
    """POSIX mode bits are meaningless on Windows, where NTFS ACLs carry custody."""
    return os.name != "nt"


def _local_sink_paths(item) -> tuple[str, bool]:
    """Validate sink paths without executing the sink or touching the network."""
    job_dir = item.get("job_dir")
    if job_dir is not None:
        directory = Path(job_dir)
        try:
            info = directory.lstat()
        except OSError:
            return "configuration_path_unavailable", False
        if (
            directory.is_symlink()
            or not directory.is_dir()
            or (_posix_mode_gate() and info.st_mode & 0o077)
        ):
            return "configuration_path_unavailable", False
    for key in _SINK_REFERENCE_FILES:
        value = item.get(key)
        if value is None:
            continue
        path = Path(value) if isinstance(value, str) else None
        try:
            info = path.lstat() if path is not None else None
        except OSError:
            return "configuration_file_missing", False
        if path is None or info is None or path.is_symlink() or not stat.S_ISREG(info.st_mode):
            return "configuration_file_missing", False
    return "registered_local_process_not_executed", True


async def diagnose(adapter, policy_label, config):
    checks = {
        "base_url": bool(adapter.base_url),
        "service_user_id": False,
        "user_fingerprint": bool(re.fullmatch(r"[A-F0-9]{40}|[A-F0-9]{64}", adapter.user_fingerprint)),
        "server_fingerprint": bool(re.fullmatch(r"[A-F0-9]{40}|[A-F0-9]{64}", adapter.server_fingerprint)),
        "auth_files_configured": bool(adapter._configured()),
        "private_key_usable": False,
        "server_public_key_present": False,
        "access_policy": False,
        "https_sink_configuration": True,
        "sink_configuration": True,
    }
    try:
        UUID(adapter.service_user_id)
        checks["service_user_id"] = True
    except (ValueError, TypeError, AttributeError):
        pass
    sinks = {}
    try:
        policy = adapter.access_policy(policy_label)
        checks["access_policy"] = True
        registered = adapter.sinks._load()
        for name in sorted(policy.sink_refs):
            item = registered[name]
            if item.get("kind") == "https_probe":
                try:
                    validate_probe(item)
                    sinks[name] = "configuration_valid_endpoint_not_checked"
                except (ValueError, TypeError):
                    sinks[name] = "invalid_configuration"
                    checks["https_sink_configuration"] = False
            else:
                status, valid = _local_sink_paths(item)
                sinks[name] = status
                if not valid:
                    checks["sink_configuration"] = False
    except Exception:
        checks["access_policy"] = False
    if checks["user_fingerprint"]:
        checks["private_key_usable"] = await adapter._gpg_preflight()
    if checks["private_key_usable"] and checks["server_fingerprint"]:
        try:
            output = await adapter._gpg(
                ["--with-colons", "--fingerprint", "--list-keys", adapter.server_fingerprint]
            )
            fingerprints = {
                line.split(":")[9]
                for line in output.splitlines()
                if line.startswith("fpr:") and len(line.split(":")) > 9
            }
            checks["server_public_key_present"] = adapter.server_fingerprint in fingerprints
        except Exception:
            pass
    return {
        "ready": all(checks.values()),
        "scope": "local_key_and_policy_checks",
        "provider_connectivity": "not_checked",
        "destination_connectivity": "not_checked",
        "checks": checks,
        "next_steps": ["check_" + key for key, passed in checks.items() if not passed],
        "secret_use": {"enabled": config.passbolt_use_enabled, "sinks": sinks},
        "write_enabled": config.passbolt_write_enabled,
        "notes": [
            "Key usability is a signature of a synthetic local marker, not vault access.",
            "An HTTP probe checks an endpoint status; it cannot establish authentication by itself.",
        ],
    }


async def local_check(config):
    class NoNetwork:
        async def request(self, *args, **kwargs):
            raise RuntimeError("doctor does not make provider requests")

    profiles = Profiles(config, NoNetwork)
    try:
        label = config.bindings[config.principal_id]
        adapter, policy, _ = profiles.for_binding(label)
        return await diagnose(adapter, policy, config)
    finally:
        profiles.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Existing local configuration")
    args = parser.parse_args(argv)
    try:
        load_config(args.config)
        result = asyncio.run(local_check(ServiceConfig.from_env()))
    except Exception:
        result = {
            "ready": False,
            "scope": "local_key_and_policy_checks",
            "provider_connectivity": "not_checked",
            "next_steps": ["check_private_provider_file_and_binding_configuration"],
        }
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["ready"] else 2)


if __name__ == "__main__":
    main()
