"""Multi-stage evaluation engine for tool permission requests.

The hook owns only deterministic verdicts: DENY for what no review may approve,
and ALLOW for what needs none, which saves the host reviewer's tokens.
Everything else defers to the host's own review — the Claude Code auto mode
classifier or the Codex approval flow.
"""

from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

from agent_sentinel import rule_engine as rules
from agent_sentinel.patch_paths import extract_paths

# Read-only tools with no side effects: auto-allow without evaluation.
# Supports fnmatch glob patterns (e.g. "mcp__*__slack_read_*").
AUTO_ALLOW_TOOLS = {
    "Grep",
    "Glob",
    "Search",
    "Skill",
    "WebFetch",
    "WebSearch",
    "mcp__claude_ai_Notion__notion-fetch",
    "mcp__claude_ai_Notion__notion-search",
    "mcp__claude_ai_Notion__notion-get-*",
    "mcp__claude_ai_Notion__notion-query-*",
    "mcp__claude_ai_Notion__notion-download-*",
    "mcp__claude_ai_Slack__slack_read_*",
    "mcp__claude_ai_Slack__slack_search_*",
    "mcp__plugin_context7_context7__*",
}

# File tools evaluated through sensitive path deny rules.
FILE_TOOLS = {"Read", "Write", "Edit"}

# Tools whose `command` runs through the shell under the Bash rules.
SHELL_TOOLS = {"Bash", "Monitor"}


def _matches(tool_name: str, patterns: set[str]) -> bool:
    """Check if a tool matches any pattern (exact string or fnmatch glob)."""
    return any(fnmatch(tool_name, pattern) for pattern in patterns)


def evaluate(hook_input: dict[str, Any]) -> tuple[str, str, str] | None:
    """Evaluate a Claude Code hook input.

    Returns (decision, reason, stage) with decision "allow", "deny", or
    "defer", or None for tools the policy does not cover.
    """
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    if tool_name in SHELL_TOOLS:
        # A Monitor WebSocket watch carries `ws` instead of a command.
        if tool_name == "Monitor" and "command" not in tool_input:
            return None
        return _evaluate_bash(tool_input, hook_input)
    elif tool_name == "apply_patch":
        return _evaluate_patch(tool_input, hook_input)
    elif tool_name in FILE_TOOLS:
        return _evaluate_file(tool_input)
    elif _matches(tool_name, AUTO_ALLOW_TOOLS):
        return "allow", f"Auto-allowed tool: {tool_name}", "AUTO_ALLOW"
    return None


def evaluate_codex(hook_input: dict[str, Any]) -> tuple[str, str, str] | None:
    """Evaluate the DENY decisions Codex PreToolUse can enforce."""
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    if tool_name == "Bash":
        result = _evaluate_bash(tool_input, hook_input)
    elif tool_name == "apply_patch":
        result = _evaluate_patch(tool_input, hook_input)
    elif tool_name in FILE_TOOLS:
        result = _evaluate_file(tool_input)
    else:
        return None
    return result if result[0] == "deny" else None


def evaluate_codex_permission_request(
    hook_input: dict[str, Any],
) -> tuple[str, str, str] | None:
    """Approve only Bash commands classified ALLOW by the shared static rules."""
    if hook_input.get("tool_name") != "Bash":
        return None
    command = hook_input.get("tool_input", {}).get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    result = _evaluate_bash({"command": command}, hook_input)
    return result if result[0] in {"allow", "deny"} else None


def codex_defer_target(hook_input: dict[str, Any]) -> tuple[str, str, str]:
    """Describe the Codex policy layer that owns a hook defer."""
    if hook_input.get("hook_event_name") == "PermissionRequest":
        return (
            "native",
            "CODEX_PERMISSION_DEFER",
            "No static ALLOW; Codex approval flow applies",
        )
    return "native", "CODEX_NATIVE", "No hook denial; Codex native policy applies"


def _evaluate_bash(tool_input: dict[str, Any], hook_input: dict[str, Any]) -> tuple[str, str, str]:
    """Evaluate a shell command via segment-aware rule matching.

    The command is split into individual segments by an in-house splitter
    (so compound commands using ``&&``, ``||``, ``;``, ``|``, ``$()``,
    ``<()``, etc. are evaluated per-segment) and each segment is checked
    against DENY -> deletion scope -> DEFER -> ALLOW with strictest-wins
    aggregation.
    """
    command = tool_input.get("command", "")
    cwd = hook_input.get("cwd", ".")

    decision, reason, matched = rules.evaluate_bash_command(command, cwd)
    if decision == "deny":
        return "deny", reason, "RULE_DENY"
    if decision == "allow":
        return "allow", reason, "RULE_ALLOW"
    return "defer", reason, "RULE_DEFER" if matched else "NO_RULE"


def _evaluate_file(tool_input: dict[str, Any]) -> tuple[str, str, str]:
    """Evaluate a file tool (Read/Write/Edit) through sensitive path rules.

    A path no rule protects defers rather than allows: the host approves
    working-directory reads and edits without review anyway, and an allow
    would also approve writes outside it and to the host's protected paths.
    """
    file_path = tool_input.get("file_path", "")

    deny_match = rules.match_sensitive_path(file_path)
    if deny_match:
        return "deny", f"Blocked by sensitive path rule: {deny_match.name}", "RULE_DENY"

    return "defer", "No sensitive path rule matched", "NO_RULE"


def _evaluate_patch(
    tool_input: dict[str, Any], hook_input: dict[str, Any]
) -> tuple[str, str, str]:
    paths = extract_paths(tool_input.get("command", ""), hook_input.get("cwd", "."))
    if not paths:
        return "deny", "Could not determine apply_patch target paths", "INPUT_DENY"

    for file_path in paths:
        deny_match = rules.match_sensitive_path(file_path)
        if deny_match:
            return (
                "deny",
                f"Blocked by sensitive path rule: {deny_match.name} ({file_path})",
                "RULE_DENY",
            )

    return "allow", "No sensitive path rule matched", "RULE_ALLOW"
