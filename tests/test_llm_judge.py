"""Tests for llm_judge module."""

import asyncio
import sys
import types
from unittest.mock import patch

from agent_sentinel.llm_judge import (
    _evaluate_sdk,
    _parse_response,
    _read_options,
    evaluate,
)


class TestParseResponse:
    def test_allow(self):
        decision, reason = _parse_response("ALLOW\nThis is safe")
        assert decision == "allow"
        assert reason == "This is safe"

    def test_deny(self):
        decision, reason = _parse_response("DENY\nThis is dangerous")
        assert decision == "deny"
        assert reason == "This is dangerous"

    def test_ask(self):
        decision, reason = _parse_response("ASK\nNeeds review")
        assert decision == "ask"
        assert reason == "Needs review"

    def test_empty_response(self):
        decision, reason = _parse_response("")
        assert decision == "ask"

    def test_unexpected_response(self):
        decision, reason = _parse_response("MAYBE\nNot sure")
        assert decision == "ask"

    def test_no_reason(self):
        decision, reason = _parse_response("ALLOW")
        assert decision == "allow"
        assert reason == "No reason provided"


class TestEvaluateSDK:
    @patch("agent_sentinel.llm_judge.asyncio.run", return_value=("allow", "Safe command"))
    def test_sdk_allow(self, mock_run):
        decision, reason = evaluate("ls -la", "/tmp")
        assert decision == "allow"
        assert reason == "Safe command"

    @patch("agent_sentinel.llm_judge.asyncio.run", return_value=("deny", "Dangerous command"))
    def test_sdk_deny(self, mock_run):
        decision, reason = evaluate("rm -rf /", "/tmp")
        assert decision == "deny"
        assert reason == "Dangerous command"

    @patch("agent_sentinel.llm_judge.asyncio.run", return_value=("ask", "Needs review"))
    def test_sdk_ask(self, mock_run):
        decision, reason = evaluate("some-command", "/tmp")
        assert decision == "ask"
        assert reason == "Needs review"

    @patch("agent_sentinel.llm_judge.time.sleep")
    @patch("agent_sentinel.llm_judge.asyncio.run", side_effect=TimeoutError("timed out"))
    def test_sdk_timeout(self, mock_run, mock_sleep):
        decision, reason = evaluate("some-command", "/tmp")
        assert decision == "ask"
        assert "timed out" in reason
        assert mock_run.call_count == 2

    @patch("agent_sentinel.llm_judge.time.sleep")
    @patch(
        "agent_sentinel.llm_judge.asyncio.run",
        side_effect=[TimeoutError("timed out"), ("allow", "Safe command")],
    )
    def test_sdk_timeout_then_success(self, mock_run, mock_sleep):
        decision, reason = evaluate("some-command", "/tmp")
        assert decision == "allow"
        assert reason == "Safe command"
        assert mock_run.call_count == 2

    @patch("agent_sentinel.llm_judge.time.sleep")
    @patch("agent_sentinel.llm_judge.asyncio.run", side_effect=TimeoutError("timed out"))
    def test_sdk_timeout_backoff_between_retries(self, mock_run, mock_sleep):
        evaluate("some-command", "/tmp")
        # Delay only between attempts, never after the final one.
        assert mock_sleep.call_count == mock_run.call_count - 1

    @patch("agent_sentinel.llm_judge.asyncio.run", side_effect=Exception("connection failed"))
    def test_sdk_error(self, mock_run):
        decision, reason = evaluate("some-command", "/tmp")
        assert decision == "ask"
        assert "connection failed" in reason
        assert mock_run.call_count == 1

    @patch(
        "agent_sentinel.llm_judge._plain_options",
        side_effect=ModuleNotFoundError("No module named 'claude_agent_sdk'"),
    )
    def test_missing_sdk_falls_to_ask(self, options):
        decision, reason = evaluate("some-command", "/tmp")
        assert decision == "ask"
        assert "unavailable" in reason


class TestReadMode:
    @patch("agent_sentinel.llm_judge.asyncio.run", return_value=("allow", "ok"))
    @patch("agent_sentinel.llm_judge._read_options", wraps=_read_options)
    def test_read_dirs_selects_read_options(self, spy_read, mock_run):
        evaluate("bash /tmp/x.sh", "/proj", read_dirs=["/tmp"])
        spy_read.assert_called_once_with("/proj", ["/tmp"])

    @patch("agent_sentinel.llm_judge.asyncio.run", return_value=("allow", "ok"))
    @patch("agent_sentinel.llm_judge._read_options")
    def test_no_read_dirs_stays_plain(self, spy_read, mock_run):
        evaluate("ls -la", "/proj")
        spy_read.assert_not_called()

    def test_read_options_grants_only_read_scoped_to_dirs(self):
        opts = _read_options("/proj", ["/tmp"])
        assert opts.allowed_tools == ["Read"]
        assert opts.tools == ["Read"]
        assert opts.cwd == "/proj"
        assert opts.add_dirs == ["/tmp"]


class _FakeResult:
    def __init__(self, subtype, result=None):
        self.subtype = subtype
        self.result = result


def _fake_sdk(messages):
    mod = types.ModuleType("claude_agent_sdk")
    mod.ResultMessage = _FakeResult

    async def query(prompt, options):
        for message in messages:
            yield message

    mod.query = query
    return mod


class TestEvaluateSDKSubtype:
    def test_success_parses_verdict(self, monkeypatch):
        fake = _fake_sdk([_FakeResult("success", "DENY\nkills iTerm")])
        monkeypatch.setitem(sys.modules, "claude_agent_sdk", fake)
        decision, reason = asyncio.run(_evaluate_sdk("p", object(), 5.0))
        assert decision == "deny"
        assert reason == "kills iTerm"

    def test_max_turns_falls_to_ask(self, monkeypatch):
        monkeypatch.setitem(
            sys.modules, "claude_agent_sdk", _fake_sdk([_FakeResult("error_max_turns")])
        )
        decision, reason = asyncio.run(_evaluate_sdk("p", object(), 5.0))
        assert decision == "ask"
        assert "error_max_turns" in reason
