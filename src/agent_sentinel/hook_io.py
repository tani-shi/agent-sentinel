"""Hook protocol I/O for Claude Code PreToolUse hooks."""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO


def read_input(stdin: TextIO | None = None) -> dict[str, Any]:
    """Read and parse JSON from stdin."""
    stream = stdin if stdin is not None else sys.stdin
    raw = stream.read()
    return json.loads(raw)


def write_output(
    decision: str,
    reason: str,
    stdout: TextIO | None = None,
) -> None:
    """Write the PreToolUse JSON response to stdout.

    Emits {"hookSpecificOutput": {"hookEventName": "PreToolUse",
    "permissionDecision": "allow"|"deny"|"ask", "permissionDecisionReason": "..."}}.

    "ask" is an explicit decision (forces a prompt) rather than an empty
    passthrough: a PreToolUse "allow" no longer short-circuits the project's
    settings.json ask/deny, and an explicit "ask" outranks any settings allow,
    so a sentinel ask always reaches the user.
    """
    stream = stdout if stdout is not None else sys.stdout
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }
    json.dump(output, stream)
    stream.write("\n")
