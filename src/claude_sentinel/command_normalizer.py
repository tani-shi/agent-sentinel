"""Command normalizer: strips prefix options between the program and its
subcommand so per-command rules can match through option clutter like
``git -c color.ui=never diff`` (which would otherwise fall through to
LLM_JUDGE).

Used by both ``rule_engine`` (for matching) and ``analyzer`` (for grouping
log records) so the two stay in sync.
"""

from __future__ import annotations

import re
import shlex
from typing import NamedTuple

# Multi-token commands: the second token meaningfully changes intent
# (``git diff`` vs ``git status``). Shared with analyzer for consistent
# grouping keys.
_MULTI_TOKEN_COMMANDS: frozenset[str] = frozenset(
    {
        "git",
        "npm",
        "yarn",
        "pnpm",
        "bun",
        "uv",
        "pip",
        "pip3",
        "cargo",
        "docker",
        "make",
        "gh",
        "aws",
        "gcloud",
        "kubectl",
        "terraform",
        "pulumi",
        "helm",
        "brew",
        "apt",
        "apt-get",
        "conda",
        "go",
        "launchctl",
        "systemctl",
        "plutil",
        "defaults",
        "crontab",
    }
)


class _OptionSpec(NamedTuple):
    flag: str
    takes_value: bool


# Per-program known prefix options that may appear between the program
# and its subcommand. Whitelist-only — unknown options halt stripping
# (``normalize_for_matching`` returns the original string in that case).
_KNOWN_PREFIX_OPTIONS: dict[str, list[_OptionSpec]] = {
    "git": [
        _OptionSpec("-C", True),
        _OptionSpec("-c", True),
        _OptionSpec("--git-dir", True),
        _OptionSpec("--work-tree", True),
        _OptionSpec("--namespace", True),
        _OptionSpec("--super-prefix", True),
        _OptionSpec("--exec-path", True),
        _OptionSpec("--no-pager", False),
        _OptionSpec("--no-replace-objects", False),
        _OptionSpec("--bare", False),
        _OptionSpec("--no-optional-locks", False),
        _OptionSpec("--literal-pathspecs", False),
        _OptionSpec("-p", False),
        _OptionSpec("-P", False),
    ],
    "npm": [
        _OptionSpec("--silent", False),
        _OptionSpec("-s", False),
        _OptionSpec("--quiet", False),
        _OptionSpec("-q", False),
        _OptionSpec("--verbose", False),
        _OptionSpec("--no-fund", False),
        _OptionSpec("--no-audit", False),
        _OptionSpec("--no-progress", False),
        _OptionSpec("--prefix", True),
        _OptionSpec("--loglevel", True),
        _OptionSpec("--workspace", True),
        _OptionSpec("-w", True),
    ],
    "yarn": [
        _OptionSpec("--silent", False),
        _OptionSpec("-s", False),
        _OptionSpec("--verbose", False),
        _OptionSpec("--cwd", True),
    ],
    "pnpm": [
        _OptionSpec("--silent", False),
        _OptionSpec("-s", False),
        _OptionSpec("--filter", True),
        _OptionSpec("-w", False),
        _OptionSpec("--workspace-root", False),
    ],
    "bun": [
        _OptionSpec("--silent", False),
        _OptionSpec("--quiet", False),
        _OptionSpec("--verbose", False),
        _OptionSpec("--cwd", True),
    ],
    "docker": [
        _OptionSpec("-q", False),
        _OptionSpec("--quiet", False),
        _OptionSpec("--debug", False),
        _OptionSpec("-D", False),
        _OptionSpec("--config", True),
        _OptionSpec("-c", True),
        _OptionSpec("--context", True),
        _OptionSpec("-H", True),
        _OptionSpec("--host", True),
        _OptionSpec("-l", True),
        _OptionSpec("--log-level", True),
        _OptionSpec("--tlscacert", True),
        _OptionSpec("--tlscert", True),
        _OptionSpec("--tlskey", True),
    ],
    "gh": [
        _OptionSpec("-R", True),
        _OptionSpec("--repo", True),
        _OptionSpec("-H", True),
        _OptionSpec("--hostname", True),
    ],
    "make": [
        _OptionSpec("-C", True),
        _OptionSpec("--directory", True),
        _OptionSpec("-f", True),
        _OptionSpec("--file", True),
        _OptionSpec("--makefile", True),
        _OptionSpec("-j", True),
        _OptionSpec("--jobs", True),
        _OptionSpec("-l", True),
        _OptionSpec("--load-average", True),
        _OptionSpec("-I", True),
        _OptionSpec("--include-dir", True),
        _OptionSpec("-W", True),
        _OptionSpec("--what-if", True),
        _OptionSpec("-s", False),
        _OptionSpec("--silent", False),
        _OptionSpec("--quiet", False),
        _OptionSpec("-i", False),
        _OptionSpec("--ignore-errors", False),
        _OptionSpec("-k", False),
        _OptionSpec("--keep-going", False),
        _OptionSpec("-n", False),
        _OptionSpec("--dry-run", False),
        _OptionSpec("--just-print", False),
        _OptionSpec("-B", False),
        _OptionSpec("--always-make", False),
        _OptionSpec("-q", False),
        _OptionSpec("--question", False),
        _OptionSpec("-r", False),
        _OptionSpec("--no-builtin-rules", False),
        _OptionSpec("-R", False),
        _OptionSpec("--no-builtin-variables", False),
        _OptionSpec("-w", False),
        _OptionSpec("--print-directory", False),
        _OptionSpec("--no-print-directory", False),
    ],
    "kubectl": [
        _OptionSpec("-n", True),
        _OptionSpec("--namespace", True),
        _OptionSpec("--context", True),
        _OptionSpec("--cluster", True),
        _OptionSpec("--kubeconfig", True),
        _OptionSpec("-s", True),
        _OptionSpec("--server", True),
        _OptionSpec("--user", True),
        _OptionSpec("--token", True),
    ],
    "go": [
        _OptionSpec("-C", True),
    ],
    "uv": [
        _OptionSpec("-q", False),
        _OptionSpec("--quiet", False),
        _OptionSpec("-v", False),
        _OptionSpec("--verbose", False),
        _OptionSpec("--no-cache", False),
        _OptionSpec("--offline", False),
        _OptionSpec("--cache-dir", True),
        _OptionSpec("--directory", True),
        _OptionSpec("--project", True),
    ],
    "cargo": [
        _OptionSpec("-q", False),
        _OptionSpec("--quiet", False),
        _OptionSpec("-v", False),
        _OptionSpec("--verbose", False),
        _OptionSpec("--frozen", False),
        _OptionSpec("--locked", False),
        _OptionSpec("--offline", False),
        _OptionSpec("--manifest-path", True),
        _OptionSpec("--config", True),
        _OptionSpec("--target-dir", True),
    ],
    "aws": [
        _OptionSpec("--no-paginate", False),
        _OptionSpec("--no-sign-request", False),
        _OptionSpec("--region", True),
        _OptionSpec("--profile", True),
        _OptionSpec("--output", True),
        _OptionSpec("--endpoint-url", True),
        _OptionSpec("--ca-bundle", True),
    ],
    "gcloud": [
        _OptionSpec("--quiet", False),
        _OptionSpec("-q", False),
        _OptionSpec("--project", True),
        _OptionSpec("--account", True),
        _OptionSpec("--configuration", True),
        _OptionSpec("--billing-project", True),
        _OptionSpec("--verbosity", True),
    ],
}


# Leading tokens that wrap a real command without changing what it does, but
# defeat start-anchored rules: `!` negation, loop/conditional body keywords,
# and single-token command runners (command/exec/builtin/time/nohup). Stripping
# them exposes the underlying command (`! kill` -> `kill`, `nohup watch` ->
# `watch`) so anchored ASK/DENY rules match. Only argument-free runners are
# listed: `env`/`timeout` take their own args before the command and cannot be
# stripped by a plain leading-token rule. Condition keywords (while/until/for/
# if/case) and body-less keywords (done/fi/esac) are intentionally excluded.
_WRAPPER_PREFIXES: frozenset[str] = frozenset(
    {"!", "do", "then", "else", "command", "exec", "builtin", "time", "nohup"}
)


def get_multi_token_commands() -> frozenset[str]:
    """Multi-token command names shared with analyzer for grouping."""
    return _MULTI_TOKEN_COMMANDS


def _strip_wrapper_prefixes(command: str) -> str:
    """Drop leading wrapper tokens so start-anchored rules see the real command."""
    s = command.lstrip()
    changed = False
    while True:
        parts = s.split(None, 1)
        if len(parts) < 2 or parts[0] not in _WRAPPER_PREFIXES:
            break
        s = parts[1].lstrip()
        changed = True
    return s if changed else command


# Command runners that prefix and then exec another command, consuming their
# own leading options/args first. Stripping them exposes the wrapped command to
# start-anchored rules (`env sudo ...` -> `sudo ...`, `timeout 5 kill -9 -1` ->
# `kill -9 -1`). Unlike _WRAPPER_PREFIXES these take arguments, so each carries
# the set of leading flags that consume a following value.
_RUNNER_VALUE_FLAGS: dict[str, frozenset[str]] = {
    "env": frozenset({"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}),
    "timeout": frozenset({"-s", "--signal", "-k", "--kill-after"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset({"-c", "--class", "-n", "--classdata", "-p", "--pid"}),
    "stdbuf": frozenset({"-i", "--input", "-o", "--output", "-e", "--error"}),
}
_DURATION = re.compile(r"\d+(\.\d+)?[smhd]?")


def _skip_runner_args(tokens: list[str], i: int) -> int:
    """``tokens[i]`` is a runner name; return the index of the wrapped command
    after consuming that runner's own assignments/options."""
    runner = tokens[i]
    value_flags = _RUNNER_VALUE_FLAGS[runner]
    i += 1
    duration_seen = False
    while i < len(tokens):
        tok = tokens[i]
        if runner == "env" and re.fullmatch(r"\w+=.*", tok):
            i += 1
            continue
        if tok == "--":
            return i + 1
        if tok.startswith(("-", "+")):
            i += 1
            if tok in value_flags and i < len(tokens):
                i += 1
            continue
        if runner == "timeout" and not duration_seen and _DURATION.fullmatch(tok):
            duration_seen = True
            i += 1
            continue
        break
    return i


def drop_leading_runners(tokens: list[str]) -> list[str]:
    """Drop leading wrapper prefixes (`!`/`do`/`exec`/…) and arg-taking command
    runners (`env`/`timeout`/`nice`/`ionice`/`stdbuf`), returning the wrapped
    command's tokens. Token-level so a dequoted script argument stays intact."""
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _WRAPPER_PREFIXES:
            i += 1
        elif tok in _RUNNER_VALUE_FLAGS:
            i = _skip_runner_args(tokens, i)
        else:
            break
    return tokens[i:]


def _strip_command_runners(command: str) -> str:
    """String form of :func:`drop_leading_runners` for rule matching
    (`env sudo ...` -> `sudo ...`). Quote loss from the shlex round-trip is
    acceptable here because the result is only regex-matched, never executed."""
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return command
    rest = drop_leading_runners(tokens)
    if not rest or len(rest) == len(tokens):
        return command
    return " ".join(rest)


def _strip_prefix_options(command: str) -> str:
    """Strip per-command prefix options between a program and its subcommand.

    ``git -c color.ui=never diff`` becomes ``git diff`` so the existing
    ``git-status`` allow-rule pattern (which only knows about ``-C``) can still
    match. Returns the input unchanged when stripping is unsafe or unnecessary:
    program not whitelisted, malformed bash, unknown option encountered,
    value-taking option without a value, or no prefix options present.
    """
    s = command.lstrip()
    if not s:
        return command

    try:
        tokens = shlex.split(s, posix=True)
    except ValueError:
        return command

    if not tokens:
        return command

    head = tokens[0]
    specs = _KNOWN_PREFIX_OPTIONS.get(head)
    if not specs:
        return command

    flag_set = {spec.flag for spec in specs if not spec.takes_value}
    value_set = {spec.flag for spec in specs if spec.takes_value}

    out: list[str] = [head]
    i = 1
    stripped_any = False
    while i < len(tokens):
        tok = tokens[i]
        if not tok.startswith("-"):
            out.extend(tokens[i:])
            break
        if "=" in tok and tok.startswith("--"):
            opt_name = tok.split("=", 1)[0]
            if opt_name in flag_set or opt_name in value_set:
                i += 1
                stripped_any = True
                continue
            out.extend(tokens[i:])
            break
        if tok in flag_set:
            i += 1
            stripped_any = True
            continue
        if tok in value_set:
            if i + 1 >= len(tokens):
                return command
            i += 2
            stripped_any = True
            continue
        out.extend(tokens[i:])
        break

    only_program_name_remains = len(out) == 1
    if not stripped_any or only_program_name_remains:
        return command
    return " ".join(out)


def normalize_for_matching(command: str) -> str:
    """Normalize a command for rule matching.

    Strips leading wrapper tokens (``! kill``, ``do rm -rf x``) and command
    runners (``env sudo ...`` -> ``sudo ...``) so start-anchored rules see the
    real command, then strips per-command prefix options (``git -c x=y diff``
    -> ``git diff``). Each pass returns its input unchanged when nothing
    applies, so an already-plain command is returned as-is.
    """
    return _strip_prefix_options(_strip_command_runners(_strip_wrapper_prefixes(command)))


def normalize_for_analysis(command: str) -> str | None:
    """Return the analyzer grouping key for a Bash command.

    Strips prefix options first so ``git -c x=y diff`` and ``git diff``
    group together under ``"git diff"`` rather than fragmenting under
    ``"git"``.
    """
    normalized = normalize_for_matching(command).strip()
    if not normalized:
        return None
    try:
        tokens = shlex.split(normalized, posix=True)
    except ValueError:
        tokens = normalized.split()
    if not tokens:
        return None
    head = tokens[0]
    if head in _MULTI_TOKEN_COMMANDS and len(tokens) >= 2:
        second = tokens[1]
        if not second.startswith("-"):
            return f"{head} {second}"
    return head
