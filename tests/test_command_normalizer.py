"""Tests for command_normalizer module."""

from claude_sentinel.command_normalizer import (
    get_multi_token_commands,
    normalize_for_analysis,
    normalize_for_matching,
)


class TestNormalizeForMatching:
    def test_git_c_config(self):
        assert normalize_for_matching("git -c color.ui=never diff") == "git diff"
        assert normalize_for_matching("git -c color.ui=never status") == "git status"

    def test_git_uppercase_C(self):
        assert normalize_for_matching("git -C /tmp/repo log --oneline") == "git log --oneline"

    def test_git_no_pager(self):
        assert normalize_for_matching("git --no-pager log --oneline") == "git log --oneline"

    def test_git_multiple_prefix_options(self):
        assert normalize_for_matching("git -C /tmp -c x=y log") == "git log"

    def test_git_c_with_destructive_subcommand(self):
        # ASK 側のフォールスルーを塞ぐためのケース
        assert normalize_for_matching("git -c safecrlf=false reset --hard") == "git reset --hard"

    def test_git_long_option_eq_form(self):
        assert normalize_for_matching("git --git-dir=/tmp/.git status") == "git status"

    def test_npm_silent(self):
        assert normalize_for_matching("npm --silent install") == "npm install"
        assert normalize_for_matching("npm -s install") == "npm install"

    def test_pnpm_silent(self):
        assert normalize_for_matching("pnpm --silent run build") == "pnpm run build"

    def test_docker_quiet(self):
        assert normalize_for_matching("docker -q ps") == "docker ps"
        assert normalize_for_matching("docker --quiet images") == "docker images"

    def test_docker_log_level_short(self):
        assert normalize_for_matching("docker -l info ps") == "docker ps"
        assert normalize_for_matching("docker --log-level=debug ps") == "docker ps"

    def test_docker_context_short(self):
        assert normalize_for_matching("docker -c default ps") == "docker ps"
        assert normalize_for_matching("docker --context=staging images") == "docker images"

    def test_gh_repo_short(self):
        assert normalize_for_matching("gh -R owner/repo pr list") == "gh pr list"

    def test_gh_repo_eq(self):
        assert normalize_for_matching("gh --repo=owner/repo issue view 123") == "gh issue view 123"

    def test_make_jobs(self):
        assert normalize_for_matching("make -j 8 build") == "make build"

    def test_make_directory(self):
        assert normalize_for_matching("make -C subdir test") == "make test"

    def test_make_silent(self):
        assert normalize_for_matching("make -s test") == "make test"

    def test_unknown_option_stops_stripping(self):
        # --unknown-flag は whitelist にない → 剥がし停止 → 元文字列
        assert normalize_for_matching("git --unknown-flag status") == "git --unknown-flag status"

    def test_non_whitelisted_program_unchanged(self):
        # ls は whitelist にないので触らない
        assert normalize_for_matching("ls -la") == "ls -la"

    def test_subcommand_options_not_touched(self):
        # subcommand 後のオプションは触らない
        assert normalize_for_matching("git push --force") == "git push --force"
        assert normalize_for_matching("npm run test --silent") == "npm run test --silent"

    def test_empty_string(self):
        assert normalize_for_matching("") == ""

    def test_whitespace_only(self):
        assert normalize_for_matching("   ") == "   "

    def test_no_prefix_options(self):
        # idempotent: 既に正規化済みのコマンドは触らない
        assert normalize_for_matching("git diff") == "git diff"
        assert normalize_for_matching("docker ps") == "docker ps"

    def test_only_options_no_subcommand(self):
        # subcommand が無く options だけのケースは元文字列を返す
        assert normalize_for_matching("git --no-pager") == "git --no-pager"
        assert normalize_for_matching("git -C /tmp") == "git -C /tmp"

    def test_value_option_missing_value(self):
        # "git -c" のように値が欠落している場合は元文字列を返す（安全側）
        assert normalize_for_matching("git -c") == "git -c"

    def test_unparseable_bash(self):
        assert normalize_for_matching("git 'unterminated") == "git 'unterminated"

    def test_strips_negation_prefix(self):
        assert normalize_for_matching("! kill -0 1") == "kill -0 1"

    def test_strips_loop_body_keyword(self):
        assert normalize_for_matching('do rm -rf "$x"') == 'rm -rf "$x"'
        assert normalize_for_matching("then git push --force") == "git push --force"
        assert normalize_for_matching("else rm -rf /") == "rm -rf /"

    def test_strips_command_wrapper(self):
        assert normalize_for_matching("exec rm -rf /") == "rm -rf /"
        assert normalize_for_matching("command git status") == "git status"
        assert normalize_for_matching("builtin rm -rf /") == "rm -rf /"
        assert normalize_for_matching("nohup watch -n1 ls") == "watch -n1 ls"
        assert normalize_for_matching("time while true") == "while true"

    def test_strips_stacked_wrappers(self):
        assert normalize_for_matching("do ! kill 1") == "kill 1"

    def test_strip_then_option_normalization(self):
        assert normalize_for_matching("do git -C /tmp status") == "git status"

    def test_condition_keywords_not_stripped(self):
        assert normalize_for_matching("until ! pgrep foo") == "until ! pgrep foo"
        assert normalize_for_matching("while true") == "while true"

    def test_strips_command_runners(self):
        assert normalize_for_matching("env sudo apt install x") == "sudo apt install x"
        assert normalize_for_matching("env FOO=bar sudo apt") == "sudo apt"
        assert normalize_for_matching("env -u PATH sudo apt") == "sudo apt"
        assert normalize_for_matching("timeout 60 kill -9 -1") == "kill -9 -1"
        assert normalize_for_matching("timeout -s TERM 5 sudo rm") == "sudo rm"
        assert normalize_for_matching("nice sudo apt") == "sudo apt"
        assert normalize_for_matching("stdbuf -oL gh pr comment 1") == "gh pr comment 1"

    def test_command_runner_not_present_unchanged(self):
        assert normalize_for_matching("sudo apt install x") == "sudo apt install x"
        assert normalize_for_matching("ls -la") == "ls -la"


class TestNormalizeForAnalysis:
    def test_git_c_config_groups_by_subcommand(self):
        assert normalize_for_analysis("git -c color.ui=never diff") == "git diff"

    def test_git_uppercase_C(self):
        assert normalize_for_analysis("git -C /tmp/repo status") == "git status"

    def test_simple_program(self):
        assert normalize_for_analysis("ls -la") == "ls"

    def test_multi_token_unknown_command(self):
        # whitelist にないが multi-token command なので "head subcommand" を返す
        assert normalize_for_analysis("flargle subcommand") == "flargle"

    def test_git_subcommand(self):
        assert normalize_for_analysis("git diff HEAD") == "git diff"

    def test_npm_run(self):
        assert normalize_for_analysis("npm run migrate:up") == "npm run"

    def test_npm_silent_install(self):
        assert normalize_for_analysis("npm --silent install") == "npm install"

    def test_flag_after_head_falls_back_to_head(self):
        # whitelist にない flag は剥がさない → 第二トークンが flag → head のみ
        assert normalize_for_analysis("git --unknown-flag") == "git"

    def test_empty(self):
        assert normalize_for_analysis("") is None
        assert normalize_for_analysis("   ") is None

    def test_unparseable_quote_falls_back(self):
        # shlex で失敗 → fallback split → "echo" が返る
        assert normalize_for_analysis("echo 'unterminated") == "echo"


class TestGetMultiTokenCommands:
    def test_contains_known_commands(self):
        cmds = get_multi_token_commands()
        assert "git" in cmds
        assert "npm" in cmds
        assert "docker" in cmds
        assert "gh" in cmds
        assert "make" in cmds

    def test_returns_frozenset(self):
        assert isinstance(get_multi_token_commands(), frozenset)
