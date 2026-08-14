"""Codex PreToolUse hook output."""

from __future__ import annotations

import json
import sys
from typing import TextIO


def write_output(decision: str, reason: str, stdout: TextIO | None = None) -> None:
    """Write only the denial response supported by Codex PreToolUse."""
    if decision != "deny":
        return

    stream = stdout if stdout is not None else sys.stdout
    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        },
        stream,
    )
    stream.write("\n")
