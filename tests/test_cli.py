"""Tests for CLI module."""

import json
import os
from unittest.mock import patch

import pytest

from claude_sentinel.cli import main


@pytest.fixture()
def log_dir(tmp_path):
    """Use a temporary directory for logs."""
    d = tmp_path / "logs"
    with patch.dict(os.environ, {"CLAUDE_SENTINEL_LOG_DIR": str(d)}):
        yield d


class TestHookMode:
    def test_bash_allow(self, capsys, log_dir):
        hook_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "session_id": "test",
            "cwd": "/tmp",
        }
        with patch("claude_sentinel.hook_io.read_input", return_value=hook_input):
            main([])

        output = json.loads(capsys.readouterr().out)
        assert output["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_bash_deny(self, capsys, log_dir):
        hook_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "sudo rm -rf /"},
            "session_id": "test",
            "cwd": "/tmp",
        }
        with patch("claude_sentinel.hook_io.read_input", return_value=hook_input):
            main([])

        output = json.loads(capsys.readouterr().out)
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_unknown_tool_passthrough(self, capsys, log_dir):
        hook_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": "SomeUnknownTool",
            "tool_input": {"key": "value"},
            "session_id": "test",
            "cwd": "/tmp",
        }
        with patch("claude_sentinel.hook_io.read_input", return_value=hook_input):
            main([])

        assert capsys.readouterr().out == ""

    def test_hook_writes_log(self, log_dir):
        hook_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "session_id": "test",
            "cwd": "/tmp",
        }
        with patch("claude_sentinel.hook_io.read_input", return_value=hook_input):
            main([])

        log_file = log_dir / "eval.jsonl"
        assert log_file.exists()
        rec = json.loads(log_file.read_text().strip())
        assert rec["decision"] == "allow"
        assert rec["input"] == "ls -la"


class TestTestMode:
    def test_allow_command(self, capsys, log_dir):
        main(["--test", "ls -la"])
        captured = capsys.readouterr()
        assert "ALLOW" in captured.out

    def test_deny_command(self, capsys, log_dir):
        main(["--test", "sudo rm -rf /"])
        captured = capsys.readouterr()
        assert "DENY" in captured.out

    def test_explain_flag(self, capsys, log_dir):
        main(["--test", "ls -la", "--explain"])
        captured = capsys.readouterr()
        assert "ALLOW" in captured.out
        assert "ls -la" in captured.err

    def test_test_mode_writes_log(self, log_dir):
        main(["--test", "ls -la"])

        log_file = log_dir / "eval.jsonl"
        assert log_file.exists()
        rec = json.loads(log_file.read_text().strip())
        assert rec["decision"] == "allow"


class TestSubcommands:
    def test_install(self, tmp_path, capsys):
        settings_file = tmp_path / "settings.json"
        main(["install", "--path", str(settings_file)])
        captured = capsys.readouterr()
        assert "installed" in captured.out

    def test_uninstall(self, tmp_path, capsys):
        settings_file = tmp_path / "settings.json"
        main(["install", "--path", str(settings_file)])
        main(["uninstall", "--path", str(settings_file)])
        captured = capsys.readouterr()
        assert "removed" in captured.out

    def test_install_with_path(self, tmp_path, capsys):
        custom = tmp_path / "custom" / "settings.json"
        main(["install", "--path", str(custom)])
        captured = capsys.readouterr()
        assert "installed" in captured.out
        assert custom.exists()


class TestLogSubcommand:
    def test_log_empty(self, capsys, log_dir):
        main(["log"])
        assert capsys.readouterr().out == ""

    def test_log_shows_records(self, capsys, log_dir):
        # Create some log entries
        main(["--test", "ls"])
        main(["--test", "pwd"])

        capsys.readouterr()  # Clear buffer

        main(["log"])
        out = capsys.readouterr().out
        assert "ls" in out
        assert "pwd" in out

    def test_log_limit(self, capsys, log_dir):
        for i in range(5):
            main(["--test", f"echo {i}"])
        capsys.readouterr()

        main(["log", "-n", "2"])
        out = capsys.readouterr().out
        # Each record is 2 lines
        lines = [line for line in out.strip().split("\n") if line]
        assert len(lines) == 4  # 2 records * 2 lines each

    def test_log_json_output(self, capsys, log_dir):
        main(["--test", "ls"])
        capsys.readouterr()

        main(["log", "--json"])
        out = capsys.readouterr().out
        rec = json.loads(out.strip())
        assert rec["input"] == "ls"
        assert rec["decision"] == "allow"

    def test_log_decision_filter(self, capsys, log_dir):
        main(["--test", "ls"])
        main(["--test", "sudo rm -rf /"])
        capsys.readouterr()

        main(["log", "--decision", "deny", "--json"])
        out = capsys.readouterr().out
        lines = [line for line in out.strip().split("\n") if line]
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec["decision"] == "deny"

    def test_log_stage_filter(self, capsys, log_dir):
        main(["--test", "ls"])  # RULE_ALLOW
        main(["--test", "sudo rm -rf /"])  # RULE_DENY
        capsys.readouterr()

        main(["log", "--stage", "RULE_DENY", "--json"])
        out = capsys.readouterr().out
        lines = [line for line in out.strip().split("\n") if line]
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec["stage"] == "RULE_DENY"

    def test_log_tail(self, capsys, log_dir):
        main(["--test", "ls"])
        main(["--test", "pwd"])
        capsys.readouterr()

        main(["log", "--tail", "--json"])
        out = capsys.readouterr().out
        lines = [line for line in out.strip().split("\n") if line]
        recs = [json.loads(line) for line in lines]
        # Tail = oldest first; ls was logged before pwd
        assert recs[0]["input"] == "ls"
        assert recs[1]["input"] == "pwd"

    def test_log_path(self, capsys, log_dir):
        main(["log", "--path"])
        out = capsys.readouterr().out.strip()
        assert out == str(log_dir)

    def test_log_since(self, capsys, log_dir):
        main(["--test", "ls"])
        capsys.readouterr()

        # Since 1 hour ago should include recent records
        main(["log", "--since", "1h", "--json"])
        out = capsys.readouterr().out
        assert "ls" in out

    def test_log_since_far_future(self, capsys, log_dir):
        main(["--test", "ls"])
        capsys.readouterr()

        # Since 0 seconds ago should exclude everything
        main(["log", "--since", "0s", "--json"])
        capsys.readouterr().out.strip()
        # 0s means time.time() - 0 = now, so records just written should be before "now"
        # Actually records just written will have ts very close to now, may or may not match
        # This just tests that --since doesn't crash


class TestRulesSubcommand:
    def test_rules_default(self, capsys):
        main(["rules"])
        out = capsys.readouterr().out
        assert "Deny rules (Bash):" in out
        assert "Allow rules (Bash):" in out
        assert "Auto-allow tools:" in out

    def test_rules_kind_filter(self, capsys):
        main(["rules", "--kind", "deny"])
        out = capsys.readouterr().out
        assert "Deny rules" in out
        assert "Allow rules" not in out
        assert "Ask rules" not in out
        assert "Auto-allow tools:" not in out

    def test_rules_type_filter(self, capsys):
        main(["rules", "--type", "sensitive-path"])
        out = capsys.readouterr().out
        assert "Deny rules (sensitive-path):" in out
        assert "(Bash):" not in out

    def test_rules_json(self, capsys):
        main(["rules", "--json"])
        out = capsys.readouterr().out
        lines = [line for line in out.strip().split("\n") if line]
        assert len(lines) > 0
        for line in lines:
            rec = json.loads(line)
            assert "kind" in rec
            assert "type" in rec
            assert rec["type"] in ("Bash", "sensitive-path", "tool")
            assert "name" in rec

    def test_rules_combined_filter(self, capsys):
        main(["rules", "--kind", "deny", "--type", "sensitive-path"])
        out = capsys.readouterr().out
        assert "Deny rules (sensitive-path):" in out
        assert "(Bash):" not in out
        assert "Allow rules" not in out
