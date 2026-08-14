"""Tests for the Codex hooks installer."""

import json
import shutil
import subprocess

import pytest

from agent_sentinel.codex_installer import install, uninstall
from agent_sentinel.codex_policy import (
    FORBIDDEN_RULES,
    HOOK_DENY_ASK_REASONS,
    HYBRID_ASK_RULES,
    NATIVE_ASK_RULES,
    PROMPT_RULES,
    render_rules,
)
from agent_sentinel.rule_engine import get_ask_rules, get_deny_rules


def test_install_preserves_existing_hooks(tmp_path):
    path = tmp_path / "hooks.json"
    path.write_text(
        json.dumps(
            {
                "description": "User hooks",
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "mcp__.*",
                            "hooks": [{"type": "command", "command": "other-hook"}],
                        }
                    ]
                },
            }
        )
    )

    install(path)

    config = json.loads(path.read_text())
    assert config["description"] == "User hooks"
    assert len(config["hooks"]["PreToolUse"]) == 2
    assert path.with_suffix(".json.bak").exists()
    assert (tmp_path / "rules" / "agent-sentinel.rules").exists()


def test_install_is_idempotent(tmp_path):
    path = tmp_path / "hooks.json"
    install(path)
    message = install(path)
    assert "already up to date" in message
    assert len(json.loads(path.read_text())["hooks"]["PreToolUse"]) == 1


def test_install_migrates_legacy_command(tmp_path):
    path = tmp_path / "hooks.json"
    path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "claude-sentinel"}],
                        }
                    ]
                }
            }
        )
    )
    install(path)
    entry = json.loads(path.read_text())["hooks"]["PreToolUse"][0]
    hook = entry["hooks"][0]
    assert hook["command"] == "agent-sentinel --host codex"
    assert entry["matcher"] == "*"


def test_install_preserves_handler_and_matcher_from_shared_group(tmp_path):
    path = tmp_path / "hooks.json"
    path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "statusMessage": "User group",
                            "hooks": [
                                {"type": "command", "command": "claude-sentinel"},
                                {"type": "command", "command": "other-hook"},
                            ],
                        }
                    ]
                }
            }
        )
    )

    install(path)

    entries = json.loads(path.read_text())["hooks"]["PreToolUse"]
    assert entries[0] == {
        "matcher": "Bash",
        "statusMessage": "User group",
        "hooks": [{"type": "command", "command": "other-hook"}],
    }
    assert entries[1] == {
        "matcher": "*",
        "hooks": [
            {
                "type": "command",
                "command": "agent-sentinel --host codex",
                "statusMessage": "Checking tool policy",
            }
        ],
    }


def test_install_consolidates_duplicate_sentinel_groups(tmp_path):
    path = tmp_path / "hooks.json"
    path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "claude-sentinel"}],
                        },
                        {
                            "matcher": "apply_patch",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "agent-sentinel --host codex",
                                }
                            ],
                        },
                    ]
                }
            }
        )
    )

    install(path)

    entries = json.loads(path.read_text())["hooks"]["PreToolUse"]
    assert entries == [
        {
            "matcher": "*",
            "hooks": [
                {
                    "type": "command",
                    "command": "agent-sentinel --host codex",
                    "statusMessage": "Checking tool policy",
                }
            ],
        }
    ]


def test_uninstall_preserves_other_hooks(tmp_path):
    path = tmp_path / "hooks.json"
    path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {"type": "command", "command": "agent-sentinel --host codex"}
                            ],
                        },
                        {
                            "matcher": "*",
                            "hooks": [{"type": "command", "command": "other-hook"}],
                        },
                    ]
                }
            }
        )
    )
    uninstall(path)
    entries = json.loads(path.read_text())["hooks"]["PreToolUse"]
    assert len(entries) == 1
    assert entries[0]["hooks"][0]["command"] == "other-hook"
    assert not (tmp_path / "rules" / "agent-sentinel.rules").exists()


def test_uninstall_preserves_handler_in_same_group(tmp_path):
    path = tmp_path / "hooks.json"
    path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "*",
                            "hooks": [
                                {"type": "command", "command": "agent-sentinel --host codex"},
                                {"type": "command", "command": "other-hook"},
                            ],
                        }
                    ]
                }
            }
        )
    )

    uninstall(path)

    entry = json.loads(path.read_text())["hooks"]["PreToolUse"][0]
    assert entry["matcher"] == "*"
    assert entry["hooks"] == [{"type": "command", "command": "other-hook"}]


def test_generated_rules_never_allow_sandbox_bypass():
    content = render_rules()
    assert 'decision = "allow"' not in content
    assert 'decision = "prompt"' in content
    assert 'decision = "forbidden"' in content


def test_every_ask_rule_has_one_codex_owner():
    prompt_sources = {rule.source for rule in PROMPT_RULES} - HYBRID_ASK_RULES
    owners = (prompt_sources, HYBRID_ASK_RULES, NATIVE_ASK_RULES, set(HOOK_DENY_ASK_REASONS))
    for index, owner in enumerate(owners):
        assert all(owner.isdisjoint(other) for other in owners[index + 1 :])
    assert set().union(*owners) == {rule.name for rule in get_ask_rules().command_rules}


def test_forbidden_rules_come_from_deny_policy():
    deny_names = {rule.name for rule in get_deny_rules().command_rules}
    assert {rule.source for rule in FORBIDDEN_RULES} <= deny_names


def test_install_backs_up_existing_managed_rules(tmp_path):
    path = tmp_path / "hooks.json"
    rules_path = tmp_path / "rules" / "agent-sentinel.rules"
    rules_path.parent.mkdir()
    rules_path.write_text("user content\n")

    install(path)

    assert rules_path.with_name("agent-sentinel.rules.bak").read_text() == "user content\n"


def test_uninstall_removes_managed_rules_and_keeps_backup(tmp_path):
    path = tmp_path / "hooks.json"
    install(path)

    uninstall(path)

    rules_path = tmp_path / "rules" / "agent-sentinel.rules"
    assert not rules_path.exists()
    assert rules_path.with_name("agent-sentinel.rules.bak").exists()


def test_warns_when_hooks_are_disabled(tmp_path):
    path = tmp_path / "hooks.json"
    (tmp_path / "config.toml").write_text("[features]\nhooks = false\n")

    message = install(path)

    assert "hooks are disabled" in message


def test_warns_for_deprecated_hook_disable_when_canonical_is_absent(tmp_path):
    path = tmp_path / "hooks.json"
    (tmp_path / "config.toml").write_text("[features]\ncodex_hooks = false\n")

    message = install(path)

    assert "hooks are disabled" in message


def test_canonical_hook_setting_wins_over_deprecated_alias(tmp_path):
    path = tmp_path / "hooks.json"
    (tmp_path / "config.toml").write_text("[features]\nhooks = true\ncodex_hooks = false\n")

    message = install(path)

    assert "hooks are disabled" not in message


def test_warns_when_approval_policy_is_never(tmp_path):
    path = tmp_path / "hooks.json"
    (tmp_path / "config.toml").write_text('approval_policy = "never"\n')

    message = install(path)

    assert "prompt rules" in message
    assert "auto-review" in message
    assert "on-request" in message


@pytest.mark.skipif(shutil.which("codex") is None, reason="Codex CLI is not installed")
def test_generated_rules_pass_execpolicy_validation(tmp_path):
    rules_path = tmp_path / "agent-sentinel.rules"
    rules_path.write_text(render_rules())

    result = subprocess.run(
        [
            "codex",
            "execpolicy",
            "check",
            "--pretty",
            "--rules",
            str(rules_path),
            "--",
            "ssh",
            "host",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert '"decision": "prompt"' in result.stdout
