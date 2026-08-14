"""Install agent-sentinel policy into Codex."""

from __future__ import annotations

import json
import shutil
import tomllib
from copy import deepcopy
from pathlib import Path

from agent_sentinel.codex_policy import render_rules

CODEX_HOME = Path.home() / ".codex"
HOOKS_PATH = CODEX_HOME / "hooks.json"
RULES_PATH = CODEX_HOME / "rules" / "agent-sentinel.rules"
CONFIG_PATH = CODEX_HOME / "config.toml"
HOOK_EVENT = "PreToolUse"
HOOK_ENTRY = {
    "matcher": "*",
    "hooks": [
        {
            "type": "command",
            "command": "agent-sentinel --host codex",
            "statusMessage": "Checking tool policy",
        }
    ],
}


def _is_sentinel_hook(hook: dict) -> bool:
    command = hook.get("command", "")
    return "agent-sentinel" in command or "claude-sentinel" in command


def install(
    path: Path | None = None,
    *,
    rules_path: Path | None = None,
    config_path: Path | None = None,
) -> str:
    hooks_path = path or HOOKS_PATH
    managed_rules_path = rules_path or _rules_path_for(hooks_path)
    codex_config_path = config_path or hooks_path.parent / "config.toml"

    hooks_changed = _install_hook(hooks_path)
    rules_changed = _install_rules(managed_rules_path)
    changes = []
    if hooks_changed:
        changes.append(f"  hook: {hooks_path}")
    if rules_changed:
        changes.append(f"  rules: {managed_rules_path}")

    if changes:
        message = "agent-sentinel installed\n" + "\n".join(changes)
    else:
        message = f"agent-sentinel is already up to date in {hooks_path.parent}"

    notices = _configuration_notices(codex_config_path)
    trust = "Open /hooks in Codex and trust the agent-sentinel hook before using it."
    return "\n".join((message, trust, *notices))


def uninstall(path: Path | None = None, *, rules_path: Path | None = None) -> str:
    hooks_path = path or HOOKS_PATH
    managed_rules_path = rules_path or _rules_path_for(hooks_path)
    hook_removed = _uninstall_hook(hooks_path)
    rules_removed = _uninstall_rules(managed_rules_path)

    if not hook_removed and not rules_removed:
        return f"agent-sentinel not found in {hooks_path.parent}"
    removed = []
    if hook_removed:
        removed.append(f"  hook: {hooks_path}")
    if rules_removed:
        removed.append(f"  rules: {managed_rules_path}")
    return "agent-sentinel removed\n" + "\n".join(removed)


def _rules_path_for(hooks_path: Path) -> Path:
    if hooks_path == HOOKS_PATH:
        return RULES_PATH
    return hooks_path.parent / "rules" / "agent-sentinel.rules"


def _install_hook(path: Path) -> bool:
    config = _load_json(path)
    entries = config.setdefault("hooks", {}).setdefault(HOOK_EVENT, [])
    normalized_entries = []
    for entry in entries:
        handlers = entry.get("hooks", [])
        kept_handlers = [hook for hook in handlers if not _is_sentinel_hook(hook)]
        if kept_handlers:
            normalized_entries.append({**entry, "hooks": kept_handlers})
    normalized_entries.append(deepcopy(HOOK_ENTRY))
    if normalized_entries == entries:
        return False
    config["hooks"][HOOK_EVENT] = normalized_entries
    _backup(path)
    _save_json(path, config)
    return True


def _install_rules(path: Path) -> bool:
    content = render_rules()
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return False
    _backup(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


def _uninstall_hook(path: Path) -> bool:
    config = _load_json(path)
    hooks = config.get("hooks", {})
    entries = hooks.get(HOOK_EVENT, [])
    filtered = []
    removed = False
    for entry in entries:
        handlers = entry.get("hooks", [])
        kept_handlers = [hook for hook in handlers if not _is_sentinel_hook(hook)]
        removed |= len(kept_handlers) != len(handlers)
        if kept_handlers:
            filtered.append({**entry, "hooks": kept_handlers})
    if not removed:
        return False
    if filtered:
        hooks[HOOK_EVENT] = filtered
    else:
        hooks.pop(HOOK_EVENT, None)
    if not hooks:
        config.pop("hooks", None)
    _backup(path)
    _save_json(path, config)
    return True


def _uninstall_rules(path: Path) -> bool:
    if not path.exists():
        return False
    _backup(path)
    path.unlink()
    return True


def _configuration_notices(path: Path) -> list[str]:
    config = _load_toml(path)
    features = config.get("features", {})
    hooks = features.get("hooks")
    legacy_hooks = features.get("codex_hooks")
    notices = []
    if hooks is False or (hooks is None and legacy_hooks is False):
        notices.append(
            "Warning: Codex hooks are disabled in config.toml; agent-sentinel's hook DENY "
            "rules will not run."
        )
    if config.get("approval_policy") == "never":
        notices.append(
            'Warning: approval_policy="never" rejects commands matched by agent-sentinel '
            "prompt rules. Native approvals and auto-review are also unavailable, so sandboxed "
            "commands delegated to Codex may run without semantic review. Use on-request for the "
            "recommended policy."
        )
    return notices


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with path.open(encoding="utf-8") as stream:
            value = json.load(stream)
    except json.JSONDecodeError as error:
        raise SystemExit(
            f"Error: {path} contains invalid JSON ({error}). Fix or remove the file, then retry."
        ) from error
    if not isinstance(value, dict):
        raise SystemExit(f"Error: {path} must contain a JSON object.")
    return value


def _load_toml(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except tomllib.TOMLDecodeError as error:
        raise SystemExit(
            f"Error: {path} contains invalid TOML ({error}). Fix the file, then retry."
        ) from error


def _backup(path: Path) -> None:
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + ".bak"))


def _save_json(path: Path, config: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        json.dump(config, stream, indent=2)
        stream.write("\n")
