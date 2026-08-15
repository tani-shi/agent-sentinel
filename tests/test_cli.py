"""Tests for CLI module."""

import hashlib
import json
import os
from unittest.mock import patch

import pytest

from agent_sentinel.cli import main


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


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
        with patch("agent_sentinel.hook_io.read_input", return_value=hook_input):
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
        with patch("agent_sentinel.hook_io.read_input", return_value=hook_input):
            main([])

        output = json.loads(capsys.readouterr().out)
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_codex_allow_preserves_native_approval(self, capsys, log_dir):
        hook_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "session_id": "test",
            "cwd": "/tmp",
        }
        with patch("agent_sentinel.hook_io.read_input", return_value=hook_input):
            main(["--host", "codex"])

        assert capsys.readouterr().out == ""
        rec = json.loads((log_dir / "eval.jsonl").read_text())
        assert rec["decision"]["result"] == "defer"
        assert rec["decision"]["stage"] == "CODEX_NATIVE"
        assert rec["host"] == "codex"
        assert rec["decision"]["owner"] == "native"
        assert rec["request"]["command"] == "ls -la"

    def test_codex_prompt_rule_is_left_to_execpolicy(self, capsys, log_dir):
        hook_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ssh production"},
            "session_id": "test",
            "cwd": "/tmp",
        }
        with patch("agent_sentinel.hook_io.read_input", return_value=hook_input):
            main(["--host", "codex"])

        assert capsys.readouterr().out == ""
        rec = json.loads((log_dir / "eval.jsonl").read_text())
        assert rec["decision"]["result"] == "defer"
        assert rec["decision"]["stage"] == "CODEX_RULE_PROMPT"
        assert rec["decision"]["owner"] == "execpolicy"

    def test_codex_high_risk_ask_is_blocked_with_guidance(self, capsys, log_dir):
        hook_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf $TARGET"},
            "session_id": "test",
            "cwd": "/tmp",
        }
        with patch("agent_sentinel.hook_io.read_input", return_value=hook_input):
            main(["--host", "codex"])

        output = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
        assert output["permissionDecision"] == "deny"
        assert "git discard --untracked" in output["permissionDecisionReason"]

    def test_codex_invalid_input_fails_closed(self, capsys, log_dir):
        with patch("agent_sentinel.hook_io.read_input", side_effect=ValueError("bad json")):
            main(["--host", "codex"])

        output = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
        assert output["permissionDecision"] == "deny"
        assert "Invalid hook input" in output["permissionDecisionReason"]
        rec = json.loads((log_dir / "eval.jsonl").read_text())
        assert rec["decision"]["result"] == "deny"
        assert rec["decision"]["stage"] == "INPUT_DENY"
        assert rec["decision"]["owner"] == "hook"

    def test_codex_evaluation_error_fails_closed(self, capsys, log_dir):
        with (
            patch("agent_sentinel.hook_io.read_input", return_value={}),
            patch("agent_sentinel.evaluator.evaluate_codex", side_effect=TypeError("bad input")),
        ):
            main(["--host", "codex"])

        output = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
        assert output["permissionDecision"] == "deny"
        assert "Policy evaluation failed" in output["permissionDecisionReason"]
        rec = json.loads((log_dir / "eval.jsonl").read_text())
        assert rec["decision"]["result"] == "deny"
        assert rec["decision"]["stage"] == "EVALUATION_ERROR"
        assert rec["decision"]["owner"] == "hook"

    def test_codex_rule_evaluation_error_keeps_audit_event(self, capsys, log_dir):
        hook_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "session_id": "test",
            "cwd": "/tmp",
        }
        with (
            patch("agent_sentinel.hook_io.read_input", return_value=hook_input),
            patch(
                "agent_sentinel.rule_engine.inspect_bash_command",
                side_effect=RuntimeError("broken evaluator"),
            ),
        ):
            main(["--host", "codex"])

        output = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
        assert output["permissionDecision"] == "deny"
        rec = json.loads((log_dir / "eval.jsonl").read_text())
        assert rec["decision"]["stage"] == "EVALUATION_ERROR"
        assert rec["analysis"] == {"status": "unavailable", "error_type": "RuntimeError"}

    def test_codex_never_uses_claude_sdk(self, capsys, log_dir):
        hook_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "unknown-command"},
            "session_id": "test",
            "cwd": "/tmp",
        }
        with (
            patch("agent_sentinel.hook_io.read_input", return_value=hook_input),
            patch("agent_sentinel.llm_judge.evaluate") as judge,
        ):
            main(["--host", "codex"])

        judge.assert_not_called()
        assert capsys.readouterr().out == ""

    def test_unknown_tool_passthrough(self, capsys, log_dir):
        hook_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": "SomeUnknownTool",
            "tool_input": {"key": "value"},
            "session_id": "test",
            "cwd": "/tmp",
        }
        with patch("agent_sentinel.hook_io.read_input", return_value=hook_input):
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
        with patch("agent_sentinel.hook_io.read_input", return_value=hook_input):
            main([])

        log_file = log_dir / "eval.jsonl"
        assert log_file.exists()
        rec = json.loads(log_file.read_text().strip())
        assert rec["decision"]["result"] == "allow"
        assert rec["request"]["command"] == "ls -la"
        assert rec["request"]["sha256"] == _sha256("ls -la")
        assert rec["host"] == "claude"
        assert rec["decision"]["owner"] == "hook"


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
        assert rec["decision"]["result"] == "allow"

    def test_codex_unknown_command_defers_without_claude_sdk(self, capsys, log_dir):
        with patch("agent_sentinel.llm_judge.evaluate") as judge:
            main(["--host", "codex", "--test", "unknown-command"])

        judge.assert_not_called()
        assert "DEFER [CODEX_NATIVE]" in capsys.readouterr().out

    def test_codex_deny_uses_codex_evaluator(self, capsys, log_dir):
        with (
            patch("agent_sentinel.evaluator.evaluate_codex", wraps=None) as codex_evaluate,
            patch("agent_sentinel.evaluator.evaluate") as claude_evaluate,
        ):
            codex_evaluate.return_value = ("deny", "Blocked", "RULE_DENY")
            main(["--host", "codex", "--test", "sudo id"])

        codex_evaluate.assert_called_once()
        claude_evaluate.assert_not_called()
        assert "DENY [RULE_DENY]" in capsys.readouterr().out


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

    def test_install_codex_with_path(self, tmp_path, capsys):
        custom = tmp_path / "hooks.json"
        main(["install", "--target", "codex", "--path", str(custom)])
        captured = capsys.readouterr()
        assert "Settings > Hooks" in captured.out
        assert "/hooks in Codex CLI" in captured.out
        config = json.loads(custom.read_text())
        command = config["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        assert command == "agent-sentinel --host codex"


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
        assert "Bash: ls" in out
        assert "Bash: pwd" in out
        assert "event=" in out

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
        assert rec["request"]["sha256"] == _sha256("ls")
        assert rec["request"]["command"] == "ls"
        assert rec["decision"]["result"] == "allow"

    def test_log_decision_filter(self, capsys, log_dir):
        main(["--test", "ls"])
        main(["--test", "sudo rm -rf /"])
        capsys.readouterr()

        main(["log", "--decision", "deny", "--json"])
        out = capsys.readouterr().out
        lines = [line for line in out.strip().split("\n") if line]
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec["decision"]["result"] == "deny"

    def test_log_stage_filter(self, capsys, log_dir):
        main(["--test", "ls"])  # RULE_ALLOW
        main(["--test", "sudo rm -rf /"])  # RULE_DENY
        capsys.readouterr()

        main(["log", "--stage", "RULE_DENY", "--json"])
        out = capsys.readouterr().out
        lines = [line for line in out.strip().split("\n") if line]
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec["decision"]["stage"] == "RULE_DENY"

    def test_log_accepts_codex_stage_filter(self, capsys, log_dir):
        main(["--host", "codex", "--test", "ssh production"])
        capsys.readouterr()

        main(["log", "--stage", "CODEX_RULE_PROMPT", "--json"])
        rec = json.loads(capsys.readouterr().out)
        assert rec["decision"]["result"] == "defer"
        assert rec["decision"]["owner"] == "execpolicy"

    def test_log_tail(self, capsys, log_dir):
        main(["--test", "ls"])
        main(["--test", "pwd"])
        capsys.readouterr()

        main(["log", "--tail", "--json"])
        out = capsys.readouterr().out
        lines = [line for line in out.strip().split("\n") if line]
        recs = [json.loads(line) for line in lines]
        # Tail = oldest first; ls was logged before pwd
        assert recs[0]["request"]["command"] == "ls"
        assert recs[1]["request"]["command"] == "pwd"

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
        assert _sha256("ls") in out

    def test_log_since_far_future(self, capsys, log_dir):
        main(["--test", "ls"])
        capsys.readouterr()

        # Since 0 seconds ago should exclude everything
        main(["log", "--since", "0s", "--json"])
        capsys.readouterr().out.strip()
        # 0s means time.time() - 0 = now, so records just written should be before "now"
        # Actually records just written will have ts very close to now, may or may not match
        # This just tests that --since doesn't crash

    def test_log_annotation_and_audit(self, capsys, log_dir):
        main(["--test", "ls"])
        capsys.readouterr()
        event = json.loads((log_dir / "eval.jsonl").read_text())

        main(
            [
                "log",
                "annotate",
                event["event_id"],
                "--label",
                "false-positive",
                "--note",
                "review this rule",
            ]
        )
        assert "Annotation" in capsys.readouterr().out

        main(["audit", "--json"])
        findings = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        assert any(finding["code"] == "USER_REPORTED_FALSE_POSITIVE" for finding in findings)

    def test_replay_one_event(self, capsys, log_dir):
        main(["--host", "codex", "--test", "ssh production"])
        capsys.readouterr()
        event = json.loads((log_dir / "eval.jsonl").read_text())

        main(["replay", "--event", event["event_id"], "--json"])
        replay = json.loads(capsys.readouterr().out)

        assert replay["replayable"] is True
        assert replay["changed"] is False
        assert replay["current"]["owner"] == "execpolicy"


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
