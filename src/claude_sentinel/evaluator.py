"""Multi-stage evaluation engine for tool permission requests."""

from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

from claude_sentinel import llm_judge
from claude_sentinel import rule_engine as rules

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

# Tools that have external impact and require user confirmation.
# Supports fnmatch glob patterns (e.g. "mcp__*__notion-create-*").
ASK_TOOLS = {
    "mcp__claude_ai_Slack__slack_send_message",
    "mcp__claude_ai_Slack__slack_send_message_draft",
    "mcp__claude_ai_Slack__slack_schedule_message",
    "mcp__claude_ai_Slack__slack_create_canvas",
    "mcp__claude_ai_Slack__slack_update_canvas",
    "mcp__claude_ai_Notion__notion-create-*",
    "mcp__claude_ai_Notion__notion-update-*",
    "mcp__claude_ai_Notion__notion-duplicate-*",
    "mcp__claude_ai_Notion__notion-move-*",
}

# File tools evaluated through sensitive path deny rules.
FILE_TOOLS = {"Read", "Write", "Edit"}


def _matches(tool_name: str, patterns: set[str]) -> bool:
    """Check if a tool matches any pattern (exact string or fnmatch glob)."""
    return any(fnmatch(tool_name, pattern) for pattern in patterns)


def evaluate(hook_input: dict[str, Any]) -> tuple[str, str, str] | None:
    """Evaluate a hook input through the multi-stage system.

    Returns:
        (decision, reason, stage) or None for passthrough (unknown tools)
    """
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    if tool_name == "Bash":
        return _evaluate_bash(tool_input, hook_input)
    elif tool_name in FILE_TOOLS:
        return _evaluate_file(tool_input)
    elif _matches(tool_name, AUTO_ALLOW_TOOLS):
        return "allow", f"Auto-allowed tool: {tool_name}", "AUTO_ALLOW"
    elif _matches(tool_name, ASK_TOOLS):
        return "ask", f"External impact tool requires confirmation: {tool_name}", "TOOL_ASK"
    else:
        # Unknown tool: passthrough
        return None


def _evaluate_bash(tool_input: dict[str, Any], hook_input: dict[str, Any]) -> tuple[str, str, str]:
    """Evaluate a Bash command via segment-aware rule matching.

    The command is split into individual segments by an in-house splitter
    (so compound commands using ``&&``, ``||``, ``;``, ``|``, ``$()``,
    ``<()``, etc. are evaluated per-segment) and each segment is checked
    against DENY -> ASK -> interpreter-escalation -> ALLOW with strictest-wins
    aggregation. A segment matched by no rule falls through to the LLM judge;
    an out-of-project script file falls through to the read judge, which is
    granted read access to that file.
    """
    command = tool_input.get("command", "")
    cwd = hook_input.get("cwd", ".")

    decision, reason, read_dirs = rules.evaluate_bash_command(command, cwd)
    if decision == "deny":
        return "deny", reason, "RULE_DENY"
    if decision == "ask":
        return "ask", reason, "RULE_ASK"
    if decision == "allow":
        return "allow", reason, "RULE_ALLOW"

    if decision == "llm_read":
        llm_decision, llm_reason = llm_judge.evaluate(command, cwd, read_dirs=read_dirs)
        return llm_decision, llm_reason, "LLM_JUDGE_READ"

    llm_decision, llm_reason = llm_judge.evaluate(command, cwd)
    return llm_decision, llm_reason, "LLM_JUDGE"


def _evaluate_file(tool_input: dict[str, Any]) -> tuple[str, str, str]:
    """Evaluate a file tool (Read/Write/Edit) through sensitive path rules."""
    file_path = tool_input.get("file_path", "")

    deny_match = rules.match_sensitive_path(file_path)
    if deny_match:
        return "deny", f"Blocked by sensitive path rule: {deny_match.name}", "RULE_DENY"

    return "allow", "No sensitive path rule matched", "RULE_ALLOW"
