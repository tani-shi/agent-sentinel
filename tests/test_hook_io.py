"""Tests for hook_io module."""

import io
import json

from agent_sentinel.hook_io import read_input


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
