import shutil
import subprocess

import pytest

from claude_sentinel import deletion_scope
from claude_sentinel.deletion_scope import classify
from claude_sentinel.rule_engine import evaluate_command


@pytest.fixture(autouse=True)
def clear_probe_cache():
    deletion_scope.reset_cache()
    yield
    deletion_scope.reset_cache()


@pytest.fixture
def no_temp_roots(monkeypatch):
    """Suppress the temp scope: pytest's tmp_path lives under a temp root, where
    the temp scope would answer before git is ever consulted."""
    monkeypatch.setattr(deletion_scope, "_temp_roots_cache", ())


class TestTempScope:
    """Targets under a temp root need no confirmation; the root does."""

    CWD = "/proj"

    @pytest.mark.parametrize(
        "target",
        [
            "/tmp/probe",
            "/private/tmp/probe",
            "/var/tmp/probe",
            "/tmp/claude-501/session/scratchpad",
            "/tmp/claude-501/*",
            "/tmp/probe/../probe2",
        ],
    )
    def test_below_temp_root_allowed(self, target):
        assert classify(f"rm -rf {target}", self.CWD, {}) == deletion_scope._TEMP_SCOPE

    @pytest.mark.parametrize("target", ["/tmp", "/tmp/", "/private/tmp", "/tmp/*", "/var/tmp/*"])
    def test_temp_root_itself_denied(self, target):
        verdict = classify(f"rm -rf {target}", self.CWD, {})
        assert verdict == deletion_scope._TEMP_ROOT

    def test_tmpdir_variable_resolved(self, monkeypatch):
        monkeypatch.setenv("TMPDIR", "/private/tmp/session-tmp")
        deletion_scope.reset_cache()
        assert classify("rm -rf $TMPDIR/probe", self.CWD, {}) == deletion_scope._TEMP_SCOPE

    def test_tmpdir_root_itself_denied(self, monkeypatch):
        monkeypatch.setenv("TMPDIR", "/private/tmp/session-tmp")
        deletion_scope.reset_cache()
        assert classify("rm -rf $TMPDIR", self.CWD, {}) == deletion_scope._TEMP_ROOT

    @pytest.mark.parametrize(
        ("segment", "assignments"),
        [
            ("rm -rf $S", {"S": "/tmp/probe"}),
            ("rm -rf ${S}", {"S": "/tmp/probe"}),
            ("rm -rf $S/sub", {"S": "/tmp/probe"}),
            ("rm -rf $S $T", {"S": "/tmp/probe", "T": "/tmp/probe2"}),
        ],
    )
    def test_assigned_target_resolved(self, segment, assignments):
        assert classify(segment, self.CWD, assignments) == deletion_scope._TEMP_SCOPE

    @pytest.mark.parametrize(
        ("segment", "assignments"),
        [
            ("rm -rf $S", {}),
            ("rm -rf $S/sub", {"T": "/tmp/probe"}),
            ("rm -rf $S", {"S": "$S"}),
            ("rm -rf $(cat target)", {}),
            ("rm -rf `cat target`", {}),
        ],
    )
    def test_unresolved_target_undecided(self, segment, assignments):
        assert classify(segment, self.CWD, assignments) is None

    def test_one_target_outside_leaves_it_undecided(self):
        assert classify("rm -rf /tmp/probe /usr/local", self.CWD, {}) is None

    @pytest.mark.parametrize(
        "segment",
        ["rm /tmp/probe", "rm -f /tmp/probe", "ls -R /tmp", "trash /tmp/probe"],
    )
    def test_non_recursive_rm_left_to_the_rules(self, segment):
        assert classify(segment, self.CWD, {}) is None

    @pytest.mark.parametrize("flag", ["-r", "-R", "-rf", "-fr", "--recursive"])
    def test_recursive_flag_forms(self, flag):
        assert classify(f"rm {flag} /tmp/probe", self.CWD, {}) == deletion_scope._TEMP_SCOPE

    def test_end_of_options_target(self):
        assert classify("rm -rf -- /tmp/-weird", self.CWD, {}) == deletion_scope._TEMP_SCOPE

    @pytest.mark.parametrize("target", ["/tmp/sess-*", "/tmp/sess-*/cache", "/tmp/*/cache"])
    def test_partial_pattern_at_the_root_undecided(self, target):
        assert classify(f"rm -rf {target}", self.CWD, {}) is None

    @pytest.mark.parametrize(
        "segment",
        [
            "rm -rf /tmp/probe > out.log",
            "rm -rf /tmp/probe >> out.log",
            "rm -rf /tmp/probe 2>/dev/null",
            "rm -rf /tmp/probe 2>&1",
            "rm -rf /tmp/probe < in.txt",
        ],
    )
    def test_redirection_filename_is_not_a_target(self, segment):
        assert classify(segment, self.CWD, {}) == deletion_scope._TEMP_SCOPE


class TestUnexpandedWord:
    """A word the shell expands into path names reaches an unknown set of files,
    so the scope declines to speak for it."""

    CWD = "/proj"

    @pytest.mark.parametrize(
        "target", ["{src,tests}", "src/{a,b}", "/tmp/{a,b}", "*.log", "build/*"]
    )
    def test_expanded_word_undecided(self, target):
        assert classify(f"rm -rf {target}", self.CWD, {}) is None

    @pytest.mark.parametrize("target", ["/etc/absent-xyz", "/usr/local/absent-xyz"])
    def test_missing_path_outside_the_working_directory_undecided(self, target):
        assert classify(f"rm -rf {target}", self.CWD, {}) is None


class TestProjectScope:
    """Inside the working directory, git decides what is recoverable."""

    @pytest.fixture
    def repo(self, tmp_path, monkeypatch, no_temp_roots):
        if shutil.which("git") is None:
            pytest.skip("git not available")
        # The developer running the tests may well have `git discard` configured
        # globally, which decides the untracked verdict.
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "absent-gitconfig"))
        monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(tmp_path / "absent-gitconfig"))
        run = lambda *args: subprocess.run(  # noqa: E731
            ["git", "-C", str(tmp_path), *args], check=True, capture_output=True
        )
        run("init")
        run("config", "user.email", "test@example.com")
        run("config", "user.name", "test")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.py").write_text("x = 1\n")
        (tmp_path / ".gitignore").write_text("build/\n")
        run("add", "-A")
        run("commit", "-m", "initial")
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "out.js").write_text("\n")
        (tmp_path / "draft").mkdir()
        (tmp_path / "draft" / "notes.md").write_text("\n")
        return tmp_path

    def test_tracked_path_denied(self, repo):
        assert classify("rm -rf src", str(repo), {}) == deletion_scope._TRACKED_PATH

    def test_repository_root_denied(self, repo):
        assert classify("rm -rf .", str(repo), {}) == deletion_scope._TRACKED_PATH

    def test_ignored_path_allowed(self, repo):
        assert classify("rm -rf build", str(repo), {}) == deletion_scope._IGNORED_PATH

    def test_missing_path_allowed(self, repo):
        assert classify("rm -rf dist", str(repo), {}) == deletion_scope._MISSING_PATH

    def test_untracked_path_asks_without_discard(self, repo):
        assert classify("rm -rf draft", str(repo), {}) is None

    def test_untracked_path_denied_with_discard(self, repo):
        subprocess.run(
            ["git", "-C", str(repo), "config", "alias.discard", "!true"],
            check=True,
            capture_output=True,
        )
        assert classify("rm -rf draft", str(repo), {}) == deletion_scope._UNTRACKED_PATH

    def test_glob_target_asks(self, repo):
        assert classify("rm -rf ./*", str(repo), {}) is None

    def test_outside_repository_asks(self, tmp_path, no_temp_roots):
        (tmp_path / "data").mkdir()
        assert classify("rm -rf data", str(tmp_path), {}) is None

    @pytest.mark.parametrize("command", ["git rm -r src", "git discard --untracked draft"])
    def test_guided_alternative_never_asks(self, command, repo):
        # The tracked and untracked deny reasons send the user to these; an ask
        # rule added over either would strand that guidance.
        assert evaluate_command(command, str(repo))[0] == "allow", command

    def test_tracked_path_wins_over_scratch_sibling(self, repo):
        result = evaluate_command(f"rm -rf /tmp/probe && rm -rf {repo}/src", str(repo))
        assert result[0] == "deny"
        assert "git rm -r" in result[1]


class TestWiredIntoEvaluation:
    CWD = "/proj"

    def test_assignment_carried_across_segments(self):
        decision, reason = evaluate_command(
            "S=/tmp/claude-501/scratchpad; rm -rf $S; mkdir -p $S", self.CWD
        )
        assert decision == "allow"
        assert "rm-temp-scope" in reason

    @pytest.mark.parametrize(
        "command",
        [
            "S=/tmp/probe; S=/usr/local; rm -rf $S",
            "S=/usr/local || S=/tmp/probe; rm -rf $S",
            "S=/usr/local && S=/tmp/probe; rm -rf $S",
            "S=/usr/local || S=/tmp/probe; S=/tmp/probe; rm -rf $S",
        ],
    )
    def test_contested_assignment_resolves_to_nothing(self, command):
        assert evaluate_command(command, self.CWD)[0] == "ask", command

    def test_repeated_identical_assignment_still_resolves(self):
        decision, _ = evaluate_command("S=/tmp/probe; S=/tmp/probe; rm -rf $S", self.CWD)
        assert decision == "allow"

    def test_assignment_after_the_deletion_is_not_used(self):
        decision, _ = evaluate_command("rm -rf $S; S=/tmp/probe", self.CWD)
        assert decision == "ask"

    def test_quoted_assignment_value_resolved(self):
        decision, _ = evaluate_command('S="/tmp/probe"; rm -rf "$S"/sub', self.CWD)
        assert decision == "allow"

    def test_command_substitution_value_not_used(self):
        decision, _ = evaluate_command("S=$(mktemp -d); rm -rf $S", self.CWD)
        assert decision == "ask"

    def test_root_deletion_still_denied(self):
        assert evaluate_command("S=/tmp/probe; rm -rf /", self.CWD)[0] == "deny"

    def test_temp_root_deny_carries_guidance(self):
        decision, reason = evaluate_command("rm -rf /tmp/*", self.CWD)
        assert decision == "deny"
        assert "not the root itself" in reason

    def test_recursive_rm_outside_scope_still_asks(self):
        assert evaluate_command("rm -rf /usr/local", self.CWD)[0] == "ask"

    def test_loop_body_prefix_still_scoped(self):
        assert evaluate_command("do rm -rf /tmp/probe", self.CWD)[0] == "allow"

    def test_inline_script_deletion_scoped(self):
        assert evaluate_command("bash -c 'rm -rf /tmp/probe'", self.CWD)[0] == "allow"
