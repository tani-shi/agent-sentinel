"""Install/uninstall claude-sentinel hooks into Claude Code settings."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from claude_sentinel import rule_engine
from claude_sentinel.evaluator import ASK_TOOLS, AUTO_ALLOW_TOOLS, FILE_TOOLS

SETTINGS_PATH = Path.home() / ".claude" / "settings.json"

HOOK_EVENT = "PreToolUse"
# Removed on install so upgrading from the pre-PreToolUse layout leaves no
# stale hook firing in parallel.
LEGACY_HOOK_EVENTS = ["PermissionRequest"]

# File tools no longer known to Claude Code. Their permission entries are
# stripped on install so a stale MultiEdit(...) deny/allow left by an earlier
# version stops triggering "matches no known tool" warnings.
LEGACY_FILE_TOOLS = ["MultiEdit"]

# Tools whose path-scoped deny rules Claude Code honors for file-permission
# checks. Write(...) is omitted: Claude Code ignores it and Edit(...) already
# covers every file-editing tool (Write/Edit/MultiEdit/NotebookEdit).
DENY_RULE_TOOLS = ("Edit", "Read")

# Deny globs for these tools are no longer generated but may linger from an
# earlier install; strip them. The bare allow entry stays (Write is still a
# live runtime tool), so in-project writes keep flowing prompt-free.
STALE_DENY_TOOLS = ["Write"]

HOOK_ENTRIES = [
    {
        "matcher": "*",
        "hooks": [
            {
                "type": "command",
                "command": "claude-sentinel",
            }
        ],
    }
]


def _get_managed_permissions() -> dict[str, list[str]]:
    """Get managed permission entries from rules and evaluator.

    File tools are blanket-allowed so ordinary in-project edits never prompt.
    The PreToolUse hook fires on every tool call, so its sensitive-path
    evaluation now sees these too, but the generated permissions.deny entries
    are kept as defense-in-depth: deny rules are evaluated before allow rules
    and before the hook, and they still guard sensitive paths on the sub-agent
    and background paths where the hook is not guaranteed to fire.
    """
    return {
        "deny": sorted(
            f"{tool}({glob})"
            for tool in DENY_RULE_TOOLS
            for glob in rule_engine.sensitive_path_globs()
        ),
        "allow": sorted(AUTO_ALLOW_TOOLS | FILE_TOOLS),
        "ask": sorted(ASK_TOOLS),
    }


def install(settings_path: Path | None = None) -> str:
    """Install claude-sentinel hooks and permissions into Claude Code settings.

    Creates a backup before modifying settings.
    Returns a status message.
    """
    path = settings_path or SETTINGS_PATH
    settings = _load_settings(path)

    # Backup
    if path.exists():
        backup = path.with_suffix(".json.bak")
        shutil.copy2(path, backup)

    # Strip permission entries Claude Code no longer honors.
    legacy_perm_removed = _remove_stale_permissions(settings)

    # Merge permissions
    managed = _get_managed_permissions()
    perm_added = {}
    for key in ("deny", "allow", "ask"):
        perm_added[key] = _merge_permissions(settings, key, managed[key])

    # Drop any hook left by an earlier layout so it does not fire in parallel.
    legacy_removed = any(_remove_hook(settings, event) for event in LEGACY_HOOK_EVENTS)

    # Merge hooks
    hooks = settings.setdefault("hooks", {})
    existing = hooks.get(HOOK_EVENT, [])
    hooks_installed = not any(
        hook.get("command") == "claude-sentinel"
        for entry in existing
        for hook in entry.get("hooks", [])
    )
    if hooks_installed:
        existing.extend(HOOK_ENTRIES)
        hooks[HOOK_EVENT] = existing

    _save_settings(path, settings)

    any_changes = (
        hooks_installed
        or legacy_removed
        or legacy_perm_removed
        or any(v > 0 for v in perm_added.values())
    )
    if not any_changes:
        return f"claude-sentinel is already up to date in {path}"

    lines = []
    if hooks_installed:
        lines.append(f"claude-sentinel installed to {path}")
    else:
        lines.append(f"claude-sentinel updated {path}")

    lines.append(f"  hooks: {'installed' if hooks_installed else 'already installed'}")
    for key in ("deny", "allow", "ask"):
        added = perm_added[key]
        total = len(settings.get("permissions", {}).get(key, []))
        if added > 0:
            existing_count = total - added
            if existing_count > 0:
                lines.append(
                    f"  permissions.{key}: {added} rules added"
                    f" ({total} total, {existing_count} existing)"
                )
            else:
                lines.append(f"  permissions.{key}: {added} rules added")
        else:
            lines.append(f"  permissions.{key}: no changes ({total} rules)")

    return "\n".join(lines)


def uninstall(settings_path: Path | None = None) -> str:
    """Remove claude-sentinel hooks and permissions from Claude Code settings.

    Returns a status message.
    """
    path = settings_path or SETTINGS_PATH
    settings = _load_settings(path)

    # Remove managed permissions, plus any stale entries left by an earlier
    # install that the current managed set no longer enumerates.
    stale_removed = _remove_stale_permissions(settings)
    managed = _get_managed_permissions()
    perm_removed = {}
    for key in ("deny", "allow", "ask"):
        perm_removed[key] = _remove_permissions(settings, key, managed[key])

    # Clean up empty permissions
    perms = settings.get("permissions", {})
    for key in ["deny", "allow", "ask"]:
        if key in perms and not perms[key]:
            del perms[key]
    if "permissions" in settings and not settings["permissions"]:
        del settings["permissions"]

    # Remove hooks (including any left by an earlier layout)
    hooks_removed = any(
        _remove_hook(settings, event) for event in (HOOK_EVENT, *LEGACY_HOOK_EVENTS)
    )

    any_changes = hooks_removed or stale_removed or any(v > 0 for v in perm_removed.values())
    if not any_changes:
        return "claude-sentinel not found in settings"

    _save_settings(path, settings)

    lines = [f"claude-sentinel removed from {path}"]
    lines.append(f"  hooks: {'removed' if hooks_removed else 'not found'}")
    for key in ("deny", "allow", "ask"):
        removed = perm_removed[key]
        remaining = len(settings.get("permissions", {}).get(key, []))
        if removed > 0:
            if remaining > 0:
                lines.append(
                    f"  permissions.{key}: {removed} rules removed"
                    f" ({remaining} user rules preserved)"
                )
            else:
                lines.append(f"  permissions.{key}: {removed} rules removed")
        else:
            lines.append(f"  permissions.{key}: not found")

    return "\n".join(lines)


def _remove_hook(settings: dict, event: str) -> bool:
    """Remove claude-sentinel entries from hooks[event]. Returns True if any removed."""
    hooks = settings.get("hooks", {})
    existing = hooks.get(event)
    if not existing:
        return False
    filtered = [
        entry
        for entry in existing
        if not any(hook.get("command") == "claude-sentinel" for hook in entry.get("hooks", []))
    ]
    if len(filtered) == len(existing):
        return False
    if filtered:
        hooks[event] = filtered
    else:
        del hooks[event]
    return True


def _remove_stale_permissions(settings: dict) -> bool:
    """Strip permission entries Claude Code no longer honors. Returns True if any removed.

    LEGACY_FILE_TOOLS have their deny globs and bare allow entry removed (the
    tool is gone). STALE_DENY_TOOLS keep their bare allow entry (Write is still
    a live runtime tool) and only shed their now-ignored path-scoped deny globs.
    """
    globs = rule_engine.sensitive_path_globs()
    removed = 0
    for tool in LEGACY_FILE_TOOLS:
        removed += _remove_permissions(settings, "deny", [f"{tool}({glob})" for glob in globs])
        removed += _remove_permissions(settings, "allow", [tool])
    for tool in STALE_DENY_TOOLS:
        removed += _remove_permissions(settings, "deny", [f"{tool}({glob})" for glob in globs])
    return removed > 0


def _merge_permissions(settings: dict, key: str, entries: list[str]) -> int:
    """Add entries to permissions[key], skipping duplicates. Returns count of added entries."""
    perms = settings.setdefault("permissions", {})
    existing = perms.setdefault(key, [])
    existing_set = set(existing)
    added = 0
    for entry in entries:
        if entry not in existing_set:
            existing.append(entry)
            existing_set.add(entry)
            added += 1
    return added


def _remove_permissions(settings: dict, key: str, entries: list[str]) -> int:
    """Remove entries from permissions[key]. Returns count of removed entries."""
    perms = settings.get("permissions", {})
    existing = perms.get(key, [])
    if not existing:
        return 0
    to_remove = set(entries)
    filtered = [e for e in existing if e not in to_remove]
    removed = len(existing) - len(filtered)
    if removed > 0:
        perms[key] = filtered
    return removed


def _load_settings(path: Path) -> dict:
    """Load settings from JSON file.

    Exits with an error on malformed JSON instead of crashing with a
    traceback, so a corrupt settings.json is never silently overwritten.
    """
    if path.exists():
        with open(path, encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as e:
                raise SystemExit(
                    f"Error: {path} contains invalid JSON ({e}). "
                    "Fix or remove the file, then retry."
                ) from e
    return {}


def _save_settings(path: Path, settings: dict) -> None:
    """Save settings to JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")
