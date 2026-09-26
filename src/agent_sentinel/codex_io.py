"""Codex hook output."""

from __future__ import annotations

import json
import sys
from typing import TextIO


def write_output(
    decision: str,
    reason: str,
    stdout: TextIO | None = None,
    *,
    event: str = "PreToolUse",
) -> None:
    """Write a decision supported by the selected Codex hook event."""
    if event == "PreToolUse":
        if decision != "deny":
            return
        output = {
            "hookEventName": event,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    elif event == "PermissionRequest":
        if decision not in {"allow", "deny"}:
            return
        request_decision = {"behavior": decision}
        if decision == "deny":
            request_decision["message"] = reason
        output = {"hookEventName": event, "decision": request_decision}
    else:
        return
    stream = stdout if stdout is not None else sys.stdout
    json.dump({"hookSpecificOutput": output}, stream)
    stream.write("\n")
