"""Tests for logger module."""

import json
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_sentinel import logger


@pytest.fixture()
def log_dir(tmp_path):
    """Use a temporary directory for logs."""
    d = tmp_path / "logs"
    with patch.dict(os.environ, {"CLAUDE_SENTINEL_LOG_DIR": str(d)}):
        yield d


def _make_hook_input(command="ls -la", tool_name="Bash", session_id="sess1", cwd="/tmp"):
    hi = {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {"command": command} if tool_name == "Bash" else {"file_path": command},
        "session_id": session_id,
        "cwd": cwd,
    }
    return hi


class TestLogEvaluation:
    def test_creates_file_and_writes_record(self, log_dir):
        hook_input = _make_hook_input("git status")
        logger.log_evaluation(
            hook_input, "allow", "Allowed by rule: git_read_only", "RULE_ALLOW", 2.1
        )

        log_file = log_dir / "eval.jsonl"
        assert log_file.exists()

        rec = json.loads(log_file.read_text().strip())
        assert rec["tool_name"] == "Bash"
        assert rec["input"] == "git status"
        assert rec["decision"] == "allow"
        assert rec["stage"] == "RULE_ALLOW"
        assert rec["reason"] == "Allowed by rule: git_read_only"
        assert rec["elapsed_ms"] == 2.1
        assert rec["session_id"] == "sess1"
        assert rec["cwd"] == "/tmp"
        assert "ts" in rec

    def test_read_tool_logs_file_path(self, log_dir):
        hook_input = _make_hook_input("/home/.env", tool_name="Read")
        logger.log_evaluation(
            hook_input, "deny", "Blocked by read rule: env_files", "RULE_DENY", 0.5
        )

        log_file = log_dir / "eval.jsonl"
        rec = json.loads(log_file.read_text().strip())
        assert rec["input"] == "/home/.env"
        assert rec["tool_name"] == "Read"

    def test_multiple_records_appended(self, log_dir):
        for i in range(5):
            logger.log_evaluation(_make_hook_input(f"cmd{i}"), "allow", "ok", "RULE_ALLOW", 1.0)

        log_file = log_dir / "eval.jsonl"
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 5

    def test_silent_on_write_failure(self, log_dir):
        """Logging failure should not raise."""
        with patch("builtins.open", side_effect=PermissionError("denied")):
            # Should not raise
            logger.log_evaluation(_make_hook_input(), "allow", "ok", "RULE_ALLOW", 1.0)


class TestRotation:
    def test_rotates_when_exceeds_max_size(self, log_dir):
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "eval.jsonl"

        # Create a file just over MAX_FILE_SIZE
        with patch.object(logger, "MAX_FILE_SIZE", 100):
            log_file.write_text("x" * 101 + "\n")
            logger.log_evaluation(_make_hook_input(), "allow", "ok", "RULE_ALLOW", 1.0)

        assert log_file.exists()  # New current file
        assert (log_dir / "eval.jsonl.1").exists()  # Rotated

    def test_rotation_shifts_existing_files(self, log_dir):
        log_dir.mkdir(parents=True, exist_ok=True)

        # Pre-create rotated files
        (log_dir / "eval.jsonl.1").write_text("old1\n")
        (log_dir / "eval.jsonl.2").write_text("old2\n")

        log_file = log_dir / "eval.jsonl"
        with patch.object(logger, "MAX_FILE_SIZE", 100):
            log_file.write_text("x" * 101 + "\n")
            logger.log_evaluation(_make_hook_input(), "allow", "ok", "RULE_ALLOW", 1.0)

        assert (log_dir / "eval.jsonl.1").read_text().startswith("x" * 101)
        assert (log_dir / "eval.jsonl.2").read_text() == "old1\n"
        assert (log_dir / "eval.jsonl.3").read_text() == "old2\n"

    def test_max_files_limit(self, log_dir):
        log_dir.mkdir(parents=True, exist_ok=True)

        with patch.object(logger, "MAX_FILE_SIZE", 100), patch.object(logger, "MAX_FILES", 3):
            # Create rotated files up to limit
            for i in range(1, 4):
                (log_dir / f"eval.jsonl.{i}").write_text(f"old{i}\n")

            log_file = log_dir / "eval.jsonl"
            log_file.write_text("x" * 101 + "\n")
            logger.log_evaluation(_make_hook_input(), "allow", "ok", "RULE_ALLOW", 1.0)

        # .3 should exist (was .2), but old .3 should have been replaced
        assert (log_dir / "eval.jsonl.3").exists()
        assert (log_dir / "eval.jsonl.3").read_text() == "old2\n"
        # .4 should NOT exist (MAX_FILES=3)
        assert not (log_dir / "eval.jsonl.4").exists()


class TestIterLogs:
    def _write_records(self, log_dir, records):
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "eval.jsonl"
        with open(log_file, "w") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")

    def test_basic_iteration(self, log_dir):
        for i in range(3):
            logger.log_evaluation(_make_hook_input(f"cmd{i}"), "allow", "ok", "RULE_ALLOW", 1.0)

        results = list(logger.iter_logs(log_dir))
        assert len(results) == 3

    def test_filter_by_decision(self, log_dir):
        logger.log_evaluation(_make_hook_input("ls"), "allow", "ok", "RULE_ALLOW", 1.0)
        logger.log_evaluation(_make_hook_input("sudo rm"), "deny", "blocked", "RULE_DENY", 0.5)
        logger.log_evaluation(_make_hook_input("cat"), "allow", "ok", "RULE_ALLOW", 1.0)

        results = list(logger.iter_logs(log_dir, decision="deny"))
        assert len(results) == 1
        assert results[0]["input"] == "sudo rm"

    def test_filter_by_stage(self, log_dir):
        logger.log_evaluation(_make_hook_input("sudo"), "deny", "blocked", "RULE_DENY", 0.5)
        logger.log_evaluation(_make_hook_input("ls"), "allow", "ok", "RULE_ALLOW", 1.0)

        results = list(logger.iter_logs(log_dir, stage="RULE_DENY"))
        assert len(results) == 1
        assert results[0]["input"] == "sudo"

    def test_filter_by_since(self, log_dir):
        now = time.time()
        self._write_records(
            log_dir,
            [
                {"ts": "2020-01-01T00:00:00+00:00", "decision": "allow", "input": "old"},
                {"ts": "2099-01-01T00:00:00+00:00", "decision": "allow", "input": "future"},
            ],
        )

        results = list(logger.iter_logs(log_dir, since=now))
        assert len(results) == 1
        assert results[0]["input"] == "future"

    def test_limit(self, log_dir):
        for i in range(10):
            logger.log_evaluation(_make_hook_input(f"cmd{i}"), "allow", "ok", "RULE_ALLOW", 1.0)

        results = list(logger.iter_logs(log_dir, limit=3))
        assert len(results) == 3

    def test_newest_first_default(self, log_dir):
        self._write_records(
            log_dir,
            [
                {"ts": "2026-01-01T00:00:00+00:00", "decision": "allow", "input": "first"},
                {"ts": "2026-01-02T00:00:00+00:00", "decision": "allow", "input": "second"},
            ],
        )

        results = list(logger.iter_logs(log_dir))
        assert results[0]["input"] == "second"
        assert results[1]["input"] == "first"

    def test_oldest_first(self, log_dir):
        self._write_records(
            log_dir,
            [
                {"ts": "2026-01-01T00:00:00+00:00", "decision": "allow", "input": "first"},
                {"ts": "2026-01-02T00:00:00+00:00", "decision": "allow", "input": "second"},
            ],
        )

        results = list(logger.iter_logs(log_dir, newest_first=False))
        assert results[0]["input"] == "first"
        assert results[1]["input"] == "second"

    def test_empty_dir(self, log_dir):
        log_dir.mkdir(parents=True, exist_ok=True)
        results = list(logger.iter_logs(log_dir))
        assert results == []


class TestGetLogDir:
    def test_default(self):
        with patch.dict(os.environ, {}, clear=True):
            # Remove CLAUDE_SENTINEL_LOG_DIR if set
            os.environ.pop("CLAUDE_SENTINEL_LOG_DIR", None)
            d = logger.get_log_dir()
            assert d == logger.DEFAULT_LOG_DIR

    def test_env_override(self):
        with patch.dict(os.environ, {"CLAUDE_SENTINEL_LOG_DIR": "/custom/logs"}):
            d = logger.get_log_dir()
            assert d == Path("/custom/logs")
