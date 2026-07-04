"""Tests for llm_judge module."""

from unittest.mock import patch

from claude_sentinel.llm_judge import _parse_response, evaluate


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
    @patch("claude_sentinel.llm_judge.asyncio.run", return_value=("allow", "Safe command"))
    def test_sdk_allow(self, mock_run):
        decision, reason = evaluate("ls -la", "/tmp")
        assert decision == "allow"
        assert reason == "Safe command"

    @patch("claude_sentinel.llm_judge.asyncio.run", return_value=("deny", "Dangerous command"))
    def test_sdk_deny(self, mock_run):
        decision, reason = evaluate("rm -rf /", "/tmp")
        assert decision == "deny"
        assert reason == "Dangerous command"

    @patch("claude_sentinel.llm_judge.asyncio.run", return_value=("ask", "Needs review"))
    def test_sdk_ask(self, mock_run):
        decision, reason = evaluate("some-command", "/tmp")
        assert decision == "ask"
        assert reason == "Needs review"

    @patch("claude_sentinel.llm_judge.time.sleep")
    @patch("claude_sentinel.llm_judge.asyncio.run", side_effect=TimeoutError("timed out"))
    def test_sdk_timeout(self, mock_run, mock_sleep):
        decision, reason = evaluate("some-command", "/tmp")
        assert decision == "ask"
        assert "timed out" in reason
        assert mock_run.call_count == 2

    @patch("claude_sentinel.llm_judge.time.sleep")
    @patch(
        "claude_sentinel.llm_judge.asyncio.run",
        side_effect=[TimeoutError("timed out"), ("allow", "Safe command")],
    )
    def test_sdk_timeout_then_success(self, mock_run, mock_sleep):
        decision, reason = evaluate("some-command", "/tmp")
        assert decision == "allow"
        assert reason == "Safe command"
        assert mock_run.call_count == 2

    @patch("claude_sentinel.llm_judge.time.sleep")
    @patch("claude_sentinel.llm_judge.asyncio.run", side_effect=TimeoutError("timed out"))
    def test_sdk_timeout_backoff_between_retries(self, mock_run, mock_sleep):
        evaluate("some-command", "/tmp")
        # Delay only between attempts, never after the final one.
        assert mock_sleep.call_count == mock_run.call_count - 1

    @patch("claude_sentinel.llm_judge.asyncio.run", side_effect=Exception("connection failed"))
    def test_sdk_error(self, mock_run):
        decision, reason = evaluate("some-command", "/tmp")
        assert decision == "ask"
        assert "connection failed" in reason
        assert mock_run.call_count == 1
