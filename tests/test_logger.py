"""Tests for logger module."""

import hashlib
import json
import os
import stat
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from agent_sentinel import codex_installer, logger
from agent_sentinel.codex_policy import render_rules
from agent_sentinel.policy_snapshot import policy_details


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


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
        assert rec["schema_version"] == 3
        assert rec["event_type"] == "evaluation"
        assert rec["event_id"]
        assert rec["request"]["tool"] == "Bash"
        assert rec["request"]["command"] == "git status"
        assert rec["request"]["sha256"] == _sha256("git status")
        assert rec["decision"]["result"] == "allow"
        assert rec["decision"]["stage"] == "RULE_ALLOW"
        assert rec["decision"]["reason"] == "Allowed by rule: git_read_only"
        assert rec["decision"]["observed_outcome"] == "unknown"
        assert rec["elapsed_ms"] == 2.1
        assert rec["session_id"] == "sess1"
        assert rec["cwd"] == "/tmp"
        assert rec["host"] == "claude"
        assert rec["decision"]["owner"] == "hook"
        assert rec["analysis"]["segments"][0]["matched_rules"] == [
            {"id": "git-status", "effect": "allow"}
        ]
        assert rec["policy"]["rules_hash"]
        assert rec["policy"]["evaluator_hash"]
        assert "ts" in rec

    def test_read_tool_logs_file_path(self, log_dir):
        hook_input = _make_hook_input("/home/.env", tool_name="Read")
        logger.log_evaluation(
            hook_input, "deny", "Blocked by read rule: env_files", "RULE_DENY", 0.5
        )

        log_file = log_dir / "eval.jsonl"
        rec = json.loads(log_file.read_text().strip())
        assert rec["request"]["sha256"] == _sha256("/home/.env")
        assert rec["request"]["file_path"] == "/home/.env"
        assert rec["request"]["tool"] == "Read"

    def test_persists_task_inputs_for_audit(self, log_dir):
        hook_input = _make_hook_input(
            "curl -H 'Authorization: Bearer secret-token' /private/customer/path",
            session_id="secret-session",
            cwd="/private/customer/project",
        )
        logger.log_evaluation(
            hook_input,
            "deny",
            "Blocked token secret-token in /private/customer/path",
            "RULE_DENY",
            0.5,
            host="codex",
            owner="hook",
        )

        rec = json.loads((log_dir / logger.LOG_FILENAME).read_text())
        assert "secret-token" in rec["request"]["command"]
        assert rec["session_id"] == "secret-session"
        assert rec["cwd"] == "/private/customer/project"
        assert "secret-token" in rec["decision"]["reason"]
        assert rec["decision"]["expected_action"] == "block"
        assert rec["decision"]["observed_outcome"] == "unknown"

    def test_excludes_write_content(self, log_dir):
        hook_input = _make_hook_input("/tmp/output.txt", tool_name="Write")
        hook_input["tool_input"]["content"] = "body that must not be retained"

        logger.log_evaluation(hook_input, "allow", "ok", "RULE_ALLOW", 0.5)

        serialized = (log_dir / logger.LOG_FILENAME).read_text()
        rec = json.loads(serialized)
        assert rec["request"]["file_path"] == "/tmp/output.txt"
        assert "body that must not be retained" not in serialized

    def test_records_normalization_and_execpolicy_coverage(self, log_dir):
        logger.log_evaluation(
            _make_hook_input("command git commit -m message"),
            "deny",
            "not representable",
            "CODEX_RULE_DENY",
            0.5,
            host="codex",
        )

        rec = json.loads((log_dir / logger.LOG_FILENAME).read_text())
        segment = rec["analysis"]["segments"][0]
        assert segment["normalized"] == "git commit -m message"
        assert segment["normalization"][0]["kind"] == "wrapper"
        assert segment["matched_rules"] == [{"id": "git-commit", "effect": "ask"}]
        assert segment["has_execpolicy_rule"] is True
        assert segment["execpolicy_covered"] is False
        assert rec["decision"]["reason_code"] == "ASK_NOT_COVERED_BY_EXECPOLICY"

    def test_policy_fingerprint_compares_installed_codex_files(self, monkeypatch, tmp_path):
        hooks_path = tmp_path / "hooks.json"
        rules_path = tmp_path / "rules" / "agent-sentinel.rules"
        rules_path.parent.mkdir()
        hooks_path.write_text(json.dumps({"hooks": {"PreToolUse": [codex_installer.HOOK_ENTRY]}}))
        rules_path.write_text(render_rules())
        monkeypatch.setattr(codex_installer, "HOOKS_PATH", hooks_path)
        monkeypatch.setattr(codex_installer, "RULES_PATH", rules_path)

        current = policy_details("codex")

        assert current["hook_definition_matches"] is True
        assert current["execpolicy_matches"] is True
        assert current["hook_definition_hash"] == current["installed_hook_definition_hash"]
        assert current["execpolicy_hash"] == current["installed_execpolicy_hash"]

        rules_path.write_text("stale rules")
        stale = policy_details("codex")

        assert stale["execpolicy_matches"] is False
        assert stale["execpolicy_hash"] != stale["installed_execpolicy_hash"]
        assert stale["policy_hash"] != current["policy_hash"]

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
    def test_log_storage_is_private(self, log_dir):
        logger.log_evaluation(_make_hook_input(), "allow", "ok", "RULE_ALLOW", 1.0)

        assert stat.S_IMODE(log_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE((log_dir / logger.LOG_FILENAME).stat().st_mode) == 0o600

    def test_multiple_records_appended(self, log_dir):
        for i in range(5):
            logger.log_evaluation(_make_hook_input(f"cmd{i}"), "allow", "ok", "RULE_ALLOW", 1.0)

        log_file = log_dir / "eval.jsonl"
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 5

    def test_annotation_is_append_only_and_not_an_evaluation(self, log_dir):
        event_id = logger.log_evaluation(
            _make_hook_input("git commit -m message"),
            "ask",
            "review",
            "RULE_ASK",
            1.0,
        )
        assert event_id is not None

        annotation_id = logger.append_annotation(event_id, "expected-prompt", "correct")

        events = list(logger.iter_events(log_dir))
        assert len(events) == 2
        annotation = next(event for event in events if event["event_type"] == "annotation")
        assert annotation["event_id"] == annotation_id
        assert annotation["target_event_id"] == event_id
        assert annotation["note"] == "correct"
        assert len(list(logger.iter_logs(log_dir))) == 1

    def test_silent_on_write_failure(self, log_dir):
        """Logging failure should not raise."""
        with patch("os.open", side_effect=PermissionError("denied")):
            # Should not raise
            logger.log_evaluation(_make_hook_input(), "allow", "ok", "RULE_ALLOW", 1.0)

    def test_new_environment_variable_takes_precedence(self, monkeypatch, tmp_path):
        new_dir = tmp_path / "new"
        legacy_dir = tmp_path / "legacy"
        monkeypatch.setenv("AGENT_SENTINEL_LOG_DIR", str(new_dir))
        monkeypatch.setenv("CLAUDE_SENTINEL_LOG_DIR", str(legacy_dir))
        assert logger.get_log_dir() == new_dir

    def test_reads_legacy_default_when_new_default_is_empty(self, monkeypatch, tmp_path):
        new_dir = tmp_path / "new"
        legacy_dir = tmp_path / "legacy"
        legacy_dir.mkdir()
        (legacy_dir / logger.LOG_FILENAME).write_text(
            json.dumps({"ts": "2026-01-01T00:00:00+00:00", "decision": "allow"}) + "\n"
        )
        monkeypatch.delenv("AGENT_SENTINEL_LOG_DIR", raising=False)
        monkeypatch.delenv("CLAUDE_SENTINEL_LOG_DIR", raising=False)
        monkeypatch.setattr(logger, "DEFAULT_LOG_DIR", new_dir)
        monkeypatch.setattr(logger, "LEGACY_LOG_DIR", legacy_dir)

        assert list(logger.iter_logs()) == [
            {"ts": "2026-01-01T00:00:00+00:00", "decision": "allow"}
        ]


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
        assert results[0]["request"]["command"] == "sudo rm"

    def test_filter_by_stage(self, log_dir):
        logger.log_evaluation(_make_hook_input("sudo"), "deny", "blocked", "RULE_DENY", 0.5)
        logger.log_evaluation(_make_hook_input("ls"), "allow", "ok", "RULE_ALLOW", 1.0)

        results = list(logger.iter_logs(log_dir, stage="RULE_DENY"))
        assert len(results) == 1
        assert results[0]["request"]["command"] == "sudo"

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
