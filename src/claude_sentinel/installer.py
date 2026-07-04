"""Install/uninstall claude-sentinel hooks into Claude Code settings."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from claude_sentinel.evaluator import ASK_TOOLS, AUTO_ALLOW_TOOLS

SETTINGS_PATH = Path.home() / ".claude" / "settings.json"

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


# Tools evaluated by the hook (not in AUTO_ALLOW_TOOLS) but allowed in settings.json.
HOOK_EVALUATED_ALLOW_TOOLS = {"Read", "Write", "Edit", "MultiEdit"}


def _get_managed_permissions() -> dict[str, list[str]]:
    """Get managed permission entries from rules and evaluator."""
    return {
        "deny": [],
        "allow": sorted(AUTO_ALLOW_TOOLS | HOOK_EVALUATED_ALLOW_TOOLS),
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

    # Merge permissions
    managed = _get_managed_permissions()
    perm_added = {}
    for key in ("deny", "allow", "ask"):
        perm_added[key] = _merge_permissions(settings, key, managed[key])

    # Merge hooks
    hooks = settings.setdefault("hooks", {})
    existing = hooks.get("PermissionRequest", [])
    hooks_installed = not any(
        hook.get("command") == "claude-sentinel"
        for entry in existing
        for hook in entry.get("hooks", [])
    )
    if hooks_installed:
        existing.extend(HOOK_ENTRIES)
        hooks["PermissionRequest"] = existing

    _save_settings(path, settings)

    any_changes = hooks_installed or any(v > 0 for v in perm_added.values())
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

    # Remove managed permissions
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

    # Remove hooks
    hooks = settings.get("hooks", {})
    existing = hooks.get("PermissionRequest", [])
    filtered = [
        entry
        for entry in existing
        if not any(hook.get("command") == "claude-sentinel" for hook in entry.get("hooks", []))
    ]
    hooks_removed = len(filtered) != len(existing)
    if hooks_removed:
        if filtered:
            hooks["PermissionRequest"] = filtered
        else:
            del hooks["PermissionRequest"]

    any_changes = hooks_removed or any(v > 0 for v in perm_removed.values())
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
