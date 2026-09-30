from functools import cache

import pytest

from agent_sentinel import deletion_scope
from agent_sentinel.deletion_scope import REVIEW, classify
from agent_sentinel.rule_engine import evaluate_command


@pytest.fixture(autouse=True)
def clear_temp_roots():
    deletion_scope.reset_temp_roots()
    yield
    deletion_scope.reset_temp_roots()


@pytest.fixture
def no_temp_roots(monkeypatch):
    """Suppress the temp scope: pytest's tmp_path lives under a temp root, where
    the temp scope would answer before the project scope.

    The replacement is cached like the real probe, so the autouse reset still
    finds a ``cache_clear`` on it.
    """
    monkeypatch.setattr(deletion_scope, "_temp_roots", cache(lambda: ()))


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
        deletion_scope.reset_temp_roots()
        assert classify("rm -rf $TMPDIR/probe", self.CWD, {}) == deletion_scope._TEMP_SCOPE

    def test_tmpdir_root_itself_denied(self, monkeypatch):
        monkeypatch.setenv("TMPDIR", "/private/tmp/session-tmp")
        deletion_scope.reset_temp_roots()
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
    def test_unresolved_target_deferred(self, segment, assignments):
        assert classify(segment, self.CWD, assignments) == REVIEW

    def test_one_target_outside_defers_all(self):
        assert classify("rm -rf /tmp/probe /usr/local", self.CWD, {}) == REVIEW

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
    def test_partial_pattern_at_the_root_deferred(self, target):
        assert classify(f"rm -rf {target}", self.CWD, {}) == REVIEW

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


class TestRootTarget:
    """The filesystem root and the home directory, whatever the command line does
    to hide them from the `rm-rf-root` regex."""

    CWD = "/proj"

    @pytest.mark.parametrize(
        "segment",
        [
            "rm -rf /",
            "rm -rf --no-preserve-root /",
            "rm -rf -v /",
            "rm -rf ~",
            "rm -rf ~/",
            "rm -rf $HOME",
            "rm -rf ${HOME}/",
        ],
    )
    def test_root_target_denied(self, segment):
        assert classify(segment, self.CWD, {}) == deletion_scope._ROOT_TARGET

    def test_path_under_home_is_not_the_root_target(self):
        assert classify("rm -rf $HOME/projects/build", self.CWD, {}) == REVIEW


class TestUnexpandedWord:
    """A word the shell expands into path names reaches an unknown set of files,
    so the scope declines to speak for it."""

    CWD = "/proj"

    @pytest.mark.parametrize(
        "target", ["{src,tests}", "src/{a,b}", "/tmp/{a,b}", "*.log", "build/*"]
    )
    def test_expanded_word_deferred(self, target):
        assert classify(f"rm -rf {target}", self.CWD, {}) == REVIEW

    @pytest.mark.parametrize("target", ["/etc/absent-xyz", "/usr/local/absent-xyz"])
    def test_missing_path_outside_the_working_directory_deferred(self, target):
        assert classify(f"rm -rf {target}", self.CWD, {}) == REVIEW


class TestProjectScope:
    """Inside the working directory only a missing target is decided; an
    existing one is left to the reviewer."""

    @pytest.fixture
    def project(self, tmp_path, no_temp_roots):
        (tmp_path / "src").mkdir()
        (tmp_path / ".env").write_text("SECRET=1\n")
        return tmp_path

    @pytest.mark.parametrize("target", ["src", ".", "./*"])
    def test_existing_target_deferred(self, project, target):
        assert classify(f"rm -rf {target}", str(project), {}) == REVIEW

    def test_secret_denied_before_the_scope(self, project):
        assert classify("rm -rf .env", str(project), {}) == REVIEW
        assert evaluate_command("rm -rf .env", str(project))[0] == "deny"
        assert evaluate_command("rm -rf src .env", str(project))[0] == "deny"

    def test_missing_path_allowed(self, project):
        assert classify("rm -rf dist", str(project), {}) == deletion_scope._MISSING_PATH

    def test_existing_target_wins_over_allowed_sibling(self, project):
        result = evaluate_command(f"rm -rf {project}/absent && rm -rf {project}/src", str(project))
        assert result == ("defer", "Matched defer rule: rm-recursive")


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
        assert evaluate_command(command, self.CWD)[0] == "defer", command

    def test_repeated_identical_assignment_still_resolves(self):
        decision, _ = evaluate_command("S=/tmp/probe; S=/tmp/probe; rm -rf $S", self.CWD)
        assert decision == "allow"

    def test_assignment_after_the_deletion_is_not_used(self):
        decision, _ = evaluate_command("rm -rf $S; S=/tmp/probe", self.CWD)
        assert decision == "defer"

    def test_quoted_assignment_value_resolved(self):
        decision, _ = evaluate_command('S="/tmp/probe"; rm -rf "$S"/sub', self.CWD)
        assert decision == "allow"

    def test_command_substitution_value_not_used(self):
        decision, _ = evaluate_command("S=$(mktemp -d); rm -rf $S", self.CWD)
        assert decision == "defer"

    def test_root_deletion_still_denied(self):
        assert evaluate_command("S=/tmp/probe; rm -rf /", self.CWD)[0] == "deny"

    def test_temp_root_deny_carries_guidance(self):
        decision, reason = evaluate_command("rm -rf /tmp/*", self.CWD)
        assert decision == "deny"
        assert "not the root itself" in reason

    def test_recursive_rm_outside_scope_deferred(self):
        assert evaluate_command("rm -rf /usr/local", self.CWD)[0] == "defer"

    def test_loop_body_prefix_still_scoped(self):
        assert evaluate_command("do rm -rf /tmp/probe", self.CWD)[0] == "allow"

    def test_inline_script_deletion_scoped(self):
        assert evaluate_command("bash -c 'rm -rf /tmp/probe'", self.CWD)[0] == "allow"
