"""Tests for Codex hook output semantics."""

import io
import json

from agent_sentinel.codex_io import write_output


def test_allow_emits_nothing():
    stdout = io.StringIO()
    write_output("allow", "Safe", stdout)
    assert stdout.getvalue() == ""


def test_deny_blocks():
    stdout = io.StringIO()
    write_output("deny", "Dangerous", stdout)
    output = json.loads(stdout.getvalue())["hookSpecificOutput"]
    assert output["permissionDecision"] == "deny"
    assert output["permissionDecisionReason"] == "Dangerous"


def test_ask_emits_nothing():
    stdout = io.StringIO()
    write_output("ask", "Needs review", stdout)
    assert stdout.getvalue() == ""
