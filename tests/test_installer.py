"""Tests for installer module."""

import json

import pytest

from claude_sentinel.installer import (
    _get_managed_permissions,
    install,
    uninstall,
)


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
        assert "PermissionRequest" in settings["hooks"]
        assert "PreToolUse" not in settings["hooks"]

        entries = settings["hooks"]["PermissionRequest"]
        assert len(entries) == 1
        assert entries[0]["hooks"][0]["command"] == "claude-sentinel"

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
        assert len(settings["hooks"]["PermissionRequest"]) == 1

    def test_install_creates_backup(self, settings_file):
        settings_file.write_text(json.dumps({"existing": True}))
        install(settings_file)

        backup = settings_file.with_suffix(".json.bak")
        assert backup.exists()
        backup_data = json.loads(backup.read_text())
        assert backup_data["existing"] is True


class TestInstallPermissions:
    def test_install_no_deny_permissions(self, settings_file, managed):
        """Sensitive path deny is handled by hook, not settings.json."""
        install(settings_file)
        settings = json.loads(settings_file.read_text())
        assert managed["deny"] == []
        perms = settings.get("permissions", {})
        assert "deny" not in perms or perms["deny"] == []

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
        assert "PermissionRequest" not in settings.get("hooks", {})

    def test_uninstall_not_installed(self, settings_file):
        settings_file.write_text(json.dumps({}))
        msg = uninstall(settings_file)
        assert "not found" in msg

    def test_uninstall_preserves_other_hooks(self, settings_file):
        settings = {
            "hooks": {
                "PermissionRequest": [
                    {"matcher": "*", "hooks": [{"type": "command", "command": "other-hook"}]},
                    {"matcher": "*", "hooks": [{"type": "command", "command": "claude-sentinel"}]},
                ]
            }
        }
        settings_file.write_text(json.dumps(settings))
        uninstall(settings_file)

        result = json.loads(settings_file.read_text())
        entries = result["hooks"]["PermissionRequest"]
        assert len(entries) == 1
        assert entries[0]["hooks"][0]["command"] == "other-hook"

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
