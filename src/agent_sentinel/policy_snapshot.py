"""Policy fingerprints and installed-policy comparisons."""

from __future__ import annotations

import hashlib
import json
from importlib import metadata, resources
from pathlib import Path
from typing import Any

from agent_sentinel import codex_policy


def policy_details(host: str) -> dict[str, Any]:
    rules_package = resources.files("agent_sentinel.rules")
    rules_content = b"".join(
        (rules_package / filename).read_bytes()
        for filename in ("deny.toml", "ask.toml", "allow.toml")
    )
    package = resources.files("agent_sentinel")
    evaluator_content = b"".join(
        (package / filename).read_bytes()
        for filename in (
            "evaluator.py",
            "rule_engine.py",
            "command_normalizer.py",
            "deletion_scope.py",
            "codex_policy.py",
        )
    )
    expected_hooks, hooks_path = _expected_hook_definition(host)
    try:
        package_version = metadata.version("agent-sentinel")
    except metadata.PackageNotFoundError:
        package_version = "unknown"
    details: dict[str, Any] = {
        "agent_sentinel_version": package_version,
        "evaluator_hash": hashlib.sha256(evaluator_content).hexdigest(),
        "rules_hash": hashlib.sha256(rules_content).hexdigest(),
        "hook_definition_hash": _digest(expected_hooks),
    }
    installed_hooks = _installed_hook_definition(hooks_path, expected_hooks)
    details["installed_hook_definition_hash"] = (
        _digest(installed_hooks) if installed_hooks is not None else ""
    )
    details["hook_definition_matches"] = installed_hooks == expected_hooks
    if host == "codex":
        from agent_sentinel.codex_installer import RULES_PATH

        expected_execpolicy = codex_policy.render_rules()
        installed_execpolicy = _read_text(RULES_PATH)
        details["execpolicy_hash"] = _digest(expected_execpolicy)
        details["installed_execpolicy_hash"] = (
            _digest(installed_execpolicy) if installed_execpolicy is not None else ""
        )
        details["execpolicy_matches"] = installed_execpolicy == expected_execpolicy
    details["policy_hash"] = _digest(details)
    return details


def _expected_hook_definition(host: str) -> tuple[Any, Path]:
    if host == "codex":
        from agent_sentinel.codex_installer import HOOK_ENTRIES, HOOKS_PATH

        return {event: [entry] for event, entry in HOOK_ENTRIES.items()}, HOOKS_PATH
    from agent_sentinel.installer import HOOK_ENTRIES, SETTINGS_PATH

    return HOOK_ENTRIES, SETTINGS_PATH


def _installed_hook_definition(path: Path, expected: Any) -> Any | None:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(config, dict):
        return None
    hooks_config = config.get("hooks", {})
    if not isinstance(hooks_config, dict):
        return None
    events = expected if isinstance(expected, dict) else {"PreToolUse": None}
    installed_by_event = {
        event: _sentinel_entries(hooks_config.get(event, [])) for event in events
    }
    return installed_by_event if isinstance(expected, dict) else installed_by_event["PreToolUse"]


def _sentinel_entries(entries: object) -> list[dict[str, Any]]:
    if not isinstance(entries, list):
        return []
    installed = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        hooks = entry.get("hooks", [])
        if not isinstance(hooks, list):
            continue
        sentinel_hooks = [
            hook
            for hook in hooks
            if isinstance(hook, dict) and "agent-sentinel" in str(hook.get("command", ""))
        ]
        if sentinel_hooks:
            installed.append({**entry, "hooks": sentinel_hooks})
    return installed


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _digest(value: Any) -> str:
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
