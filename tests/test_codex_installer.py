"""Tests for the Codex hooks installer."""

import json

from agent_sentinel.codex_installer import install, uninstall


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
    assert set(config["hooks"]) == {"PreToolUse"}
    assert path.with_suffix(".json.bak").exists()
    assert (tmp_path / "rules" / "agent-sentinel.rules").exists()


def test_install_is_idempotent(tmp_path):
    path = tmp_path / "hooks.json"
    install(path)
    message = install(path)
    assert "already up to date" in message
    assert "Trust the agent-sentinel hook" not in message
    assert len(json.loads(path.read_text())["hooks"]["PreToolUse"]) == 1


def test_install_replaces_stale_matcher(tmp_path):
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
                                {"type": "command", "command": "agent-sentinel --host codex"},
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
                            "hooks": [
                                {"type": "command", "command": "agent-sentinel --host codex"}
                            ],
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


def test_uninstall_removes_all_managed_events(tmp_path):
    path = tmp_path / "hooks.json"
    install(path)

    uninstall(path)

    assert "hooks" not in json.loads(path.read_text())


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

    assert "Codex GUI" in message
    assert "prompt rules" in message
    assert "ASK enforcement is not guaranteed" in message
    assert "auto-review" in message
    assert "on-request" in message
