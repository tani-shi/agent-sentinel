"""Tests for installer module."""

import json

import pytest

from claude_sentinel.installer import (
    _get_managed_permissions,
    install,
    uninstall,
)

WRAPPER_COMMAND = "zsh ~/.claude/scripts/claude-sentinel-wrapper.zsh"


def _settings_with_wrapper_hook():
    return {
        "hooks": {
            "PreToolUse": [
                {"matcher": "*", "hooks": [{"type": "command", "command": WRAPPER_COMMAND}]}
            ]
        }
    }


@pytest.fixture
def settings_file(tmp_path):
    return tmp_path / "settings.json"


@pytest.fixture
def managed():
    return _get_managed_permissions()


class TestInstall:
    def test_install_fresh(self, settings_file):
        msg = install(settings_file)
        assert "installed to" in msg
        assert "hooks: installed" in msg
        assert "rules added" in msg

        settings = json.loads(settings_file.read_text())
        assert "PreToolUse" in settings["hooks"]
        assert "PermissionRequest" not in settings["hooks"]

        entries = settings["hooks"]["PreToolUse"]
        assert len(entries) == 1
        assert entries[0]["hooks"][0]["command"] == "claude-sentinel"

    def test_install_migrates_legacy_permissionrequest_hook(self, settings_file):
        settings_file.write_text(
            json.dumps(
                {
                    "hooks": {
                        "PermissionRequest": [
                            {
                                "matcher": "*",
                                "hooks": [{"type": "command", "command": "claude-sentinel"}],
                            }
                        ]
                    }
                }
            )
        )
        install(settings_file)

        settings = json.loads(settings_file.read_text())
        assert "PermissionRequest" not in settings["hooks"]
        assert len(settings["hooks"]["PreToolUse"]) == 1
        assert settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "claude-sentinel"

    def test_install_strips_legacy_multiedit_permissions(self, settings_file):
        settings_file.write_text(
            json.dumps(
                {
                    "permissions": {
                        "deny": ["MultiEdit(**/.env)", "MultiEdit(**/.ssh/**)"],
                        "allow": ["MultiEdit"],
                    }
                }
            )
        )
        install(settings_file)

        settings = json.loads(settings_file.read_text())
        assert not any(e.startswith("MultiEdit(") for e in settings["permissions"]["deny"])
        assert "MultiEdit" not in settings["permissions"]["allow"]

    def test_install_strips_stale_write_deny_but_keeps_allow(self, settings_file):
        settings_file.write_text(
            json.dumps(
                {
                    "permissions": {
                        "deny": ["Write(**/.env)", "Write(**/.ssh/**)"],
                        "allow": ["Write"],
                    }
                }
            )
        )
        install(settings_file)

        settings = json.loads(settings_file.read_text())
        assert not any(e.startswith("Write(") for e in settings["permissions"]["deny"])
        assert "Write" in settings["permissions"]["allow"]

    def test_install_strips_retired_env_glob_deny(self, settings_file):
        """The `**/.env.*` glob was retired so template env files (`.env.example`)
        are writable; its stale deny entries must be shed from existing installs."""
        settings_file.write_text(
            json.dumps(
                {
                    "permissions": {
                        "deny": ["Edit(**/.env.*)", "Read(**/.env.*)", "Edit(**/.env)"],
                    }
                }
            )
        )
        install(settings_file)

        deny = json.loads(settings_file.read_text())["permissions"]["deny"]
        assert "Edit(**/.env.*)" not in deny
        assert "Read(**/.env.*)" not in deny
        assert "Edit(**/.env)" in deny

    def test_install_malformed_settings(self, settings_file):
        settings_file.write_text("{not valid json")
        with pytest.raises(SystemExit, match="invalid JSON"):
            install(settings_file)
        # The malformed file must be left untouched.
        assert settings_file.read_text() == "{not valid json"

    def test_install_existing_settings(self, settings_file):
        settings_file.write_text(json.dumps({"someKey": "value"}))
        install(settings_file)

        settings = json.loads(settings_file.read_text())
        assert settings["someKey"] == "value"
        assert "hooks" in settings

    def test_install_idempotent(self, settings_file):
        install(settings_file)
        msg = install(settings_file)
        assert "already up to date" in msg

        settings = json.loads(settings_file.read_text())
        assert len(settings["hooks"]["PreToolUse"]) == 1

    def test_install_recognizes_wrapper_hook(self, settings_file):
        settings_file.write_text(json.dumps(_settings_with_wrapper_hook()))
        msg = install(settings_file)
        assert "hooks: already installed" in msg

        settings = json.loads(settings_file.read_text())
        entries = settings["hooks"]["PreToolUse"]
        assert len(entries) == 1
        assert entries[0]["hooks"][0]["command"] == WRAPPER_COMMAND

    def test_install_creates_backup(self, settings_file):
        settings_file.write_text(json.dumps({"existing": True}))
        install(settings_file)

        backup = settings_file.with_suffix(".json.bak")
        assert backup.exists()
        backup_data = json.loads(backup.read_text())
        assert backup_data["existing"] is True


class TestInstallPermissions:
    def test_install_adds_sensitive_path_deny(self, settings_file, managed):
        """Sensitive paths are denied via settings.json permission rules as
        defense-in-depth for the sub-agent/background paths where the hook is
        not guaranteed to fire."""
        install(settings_file)
        settings = json.loads(settings_file.read_text())
        deny = settings["permissions"]["deny"]
        assert set(managed["deny"]).issubset(set(deny))
        for tool in ("Read", "Edit"):
            assert f"{tool}(**/.env)" in deny
            # `**/.env.*` is a retired glob, no longer generated.
            assert f"{tool}(**/.env.*)" not in deny
            assert f"{tool}(**/.ssh/**)" in deny
            assert f"{tool}(**/.aws/**)" in deny
        # Write(...) deny rules are not honored by Claude Code's file-permission
        # checks (Edit(...) covers all editing tools), so none are generated.
        assert not any(e.startswith("Write(") for e in deny)

    def test_managed_deny_covers_every_sensitive_path_rule(self, managed):
        from claude_sentinel.rule_engine import get_deny_rules

        for rule in get_deny_rules().sensitive_path_rules:
            assert rule.path_globs, f"{rule.name} has no path_glob"
            for glob in rule.path_globs:
                assert f"Read({glob})" in managed["deny"]

    def test_install_adds_permissions_allow(self, settings_file, managed):
        install(settings_file)
        settings = json.loads(settings_file.read_text())
        assert set(managed["allow"]).issubset(set(settings["permissions"]["allow"]))

    def test_install_adds_permissions_ask(self, settings_file, managed):
        install(settings_file)
        settings = json.loads(settings_file.read_text())
        assert set(managed["ask"]).issubset(set(settings["permissions"]["ask"]))

    def test_install_permissions_idempotent(self, settings_file, managed):
        install(settings_file)
        install(settings_file)
        settings = json.loads(settings_file.read_text())
        assert settings["permissions"]["allow"].count(managed["allow"][0]) == 1
        assert settings["permissions"]["ask"].count(managed["ask"][0]) == 1

    def test_install_adds_read_write_edit_to_allow(self, settings_file):
        install(settings_file)
        settings = json.loads(settings_file.read_text())
        allow = settings["permissions"]["allow"]
        assert "Read" in allow
        assert "Write" in allow
        assert "Edit" in allow

    def test_install_preserves_user_permissions(self, settings_file):
        settings_file.write_text(
            json.dumps(
                {
                    "permissions": {
                        "deny": ["Bash(rm -rf /*)"],
                        "allow": ["MyCustomTool"],
                        "ask": ["AnotherCustomTool"],
                    }
                }
            )
        )
        install(settings_file)
        settings = json.loads(settings_file.read_text())
        assert "Bash(rm -rf /*)" in settings["permissions"]["deny"]
        assert "MyCustomTool" in settings["permissions"]["allow"]
        assert "AnotherCustomTool" in settings["permissions"]["ask"]

    def test_install_preserves_existing_hooks(self, settings_file):
        settings_file.write_text(
            json.dumps(
                {
                    "hooks": {
                        "Notification": [
                            {
                                "matcher": "*",
                                "hooks": [{"type": "command", "command": "notify-send"}],
                            }
                        ],
                        "Stop": [
                            {
                                "matcher": "*",
                                "hooks": [{"type": "command", "command": "cleanup-script"}],
                            }
                        ],
                    }
                }
            )
        )
        install(settings_file)
        settings = json.loads(settings_file.read_text())
        assert "Notification" in settings["hooks"]
        assert "Stop" in settings["hooks"]
        assert settings["hooks"]["Notification"][0]["hooks"][0]["command"] == "notify-send"
        assert settings["hooks"]["Stop"][0]["hooks"][0]["command"] == "cleanup-script"


class TestUninstall:
    def test_uninstall(self, settings_file):
        install(settings_file)
        msg = uninstall(settings_file)
        assert "removed from" in msg
        assert "hooks: removed" in msg
        assert "rules removed" in msg

        settings = json.loads(settings_file.read_text())
        assert "PreToolUse" not in settings.get("hooks", {})

    def test_uninstall_not_installed(self, settings_file):
        settings_file.write_text(json.dumps({}))
        msg = uninstall(settings_file)
        assert "not found" in msg

    @pytest.mark.parametrize("sentinel_command", ["claude-sentinel", WRAPPER_COMMAND])
    def test_uninstall_preserves_other_hooks(self, settings_file, sentinel_command):
        settings = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "*", "hooks": [{"type": "command", "command": "other-hook"}]},
                    {"matcher": "*", "hooks": [{"type": "command", "command": sentinel_command}]},
                ]
            }
        }
        settings_file.write_text(json.dumps(settings))
        uninstall(settings_file)

        result = json.loads(settings_file.read_text())
        entries = result["hooks"]["PreToolUse"]
        assert len(entries) == 1
        assert entries[0]["hooks"][0]["command"] == "other-hook"

    def test_uninstall_removes_wrapper_hook(self, settings_file):
        settings_file.write_text(json.dumps(_settings_with_wrapper_hook()))
        uninstall(settings_file)

        settings = json.loads(settings_file.read_text())
        assert "PreToolUse" not in settings.get("hooks", {})

    def test_uninstall_removes_permissions(self, settings_file, managed):
        install(settings_file)
        uninstall(settings_file)

        settings = json.loads(settings_file.read_text())
        perms = settings.get("permissions", {})
        for entry in managed["deny"]:
            assert entry not in perms.get("deny", [])
        for entry in managed["allow"]:
            assert entry not in perms.get("allow", [])
        for entry in managed["ask"]:
            assert entry not in perms.get("ask", [])

    def test_uninstall_removes_stale_write_deny(self, settings_file):
        # A legacy install left Write(...) deny globs the current managed set no
        # longer enumerates; uninstall must still shed them.
        settings_file.write_text(
            json.dumps({"permissions": {"deny": ["Write(**/.env)", "Write(**/.ssh/**)"]}})
        )
        uninstall(settings_file)

        settings = json.loads(settings_file.read_text())
        deny = settings.get("permissions", {}).get("deny", [])
        assert not any(e.startswith("Write(") for e in deny)

    def test_uninstall_preserves_user_permissions(self, settings_file):
        settings_file.write_text(
            json.dumps(
                {
                    "permissions": {
                        "deny": ["Bash(rm -rf /*)"],
                        "allow": ["MyCustomTool"],
                        "ask": ["AnotherCustomTool"],
                    }
                }
            )
        )
        install(settings_file)
        msg = uninstall(settings_file)
        assert "user rules preserved" in msg

        settings = json.loads(settings_file.read_text())
        assert "Bash(rm -rf /*)" in settings["permissions"]["deny"]
        assert "MyCustomTool" in settings["permissions"]["allow"]
        assert "AnotherCustomTool" in settings["permissions"]["ask"]

    def test_uninstall_cleans_empty_permissions(self, settings_file):
        install(settings_file)
        uninstall(settings_file)

        settings = json.loads(settings_file.read_text())
        assert "permissions" not in settings
