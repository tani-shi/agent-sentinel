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
    *,
    updated_input: dict[str, Any] | None = None,
) -> None:
    """Write the PreToolUse JSON response to stdout.

    Emits {"hookSpecificOutput": {"hookEventName": "PreToolUse",
    "permissionDecision": "allow"|"deny", "permissionDecisionReason": "..."}}.

    A deferred call writes nothing: Claude Code's own "defer" value pauses a
    headless session instead of handing the call to its permission flow.
    This function writes a hook response; it cannot observe the host outcome.
    """
    stream = stdout if stdout is not None else sys.stdout
    specific: dict[str, Any] = {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }
    if updated_input is not None:
        specific["updatedInput"] = updated_input
    output = {"hookSpecificOutput": specific}
    json.dump(output, stream)
    stream.write("\n")
