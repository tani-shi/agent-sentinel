"""Tests for hook_io module."""

import io
import json

from claude_sentinel.hook_io import read_input, write_output


class TestReadInput:
    def test_read_valid_json(self):
        data = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        stdin = io.StringIO(json.dumps(data))
        result = read_input(stdin)
        assert result == data

    def test_read_complex_input(self):
        data = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "session_id": "abc123",
            "cwd": "/tmp",
        }
        stdin = io.StringIO(json.dumps(data))
        result = read_input(stdin)
        assert result["tool_name"] == "Bash"
        assert result["cwd"] == "/tmp"


class TestWriteOutput:
    def test_allow(self):
        stdout = io.StringIO()
        write_output("allow", "Safe command", stdout)
        hook_output = json.loads(stdout.getvalue())["hookSpecificOutput"]
        assert hook_output["permissionDecision"] == "allow"
        assert hook_output["permissionDecisionReason"] == "Safe command"

    def test_deny(self):
        stdout = io.StringIO()
        write_output("deny", "Dangerous", stdout)
        hook_output = json.loads(stdout.getvalue())["hookSpecificOutput"]
        assert hook_output["permissionDecision"] == "deny"
        assert hook_output["permissionDecisionReason"] == "Dangerous"

    def test_ask_is_explicit(self):
        stdout = io.StringIO()
        write_output("ask", "Need review", stdout)
        hook_output = json.loads(stdout.getvalue())["hookSpecificOutput"]
        assert hook_output["permissionDecision"] == "ask"
        assert hook_output["permissionDecisionReason"] == "Need review"

    def test_hook_event_name(self):
        stdout = io.StringIO()
        write_output("allow", "OK", stdout)
        output = json.loads(stdout.getvalue())
        assert output["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
