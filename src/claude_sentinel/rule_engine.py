"""TOML rule loading and regex matching."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import tomllib
from dataclasses import dataclass, field
from functools import cache
from importlib import resources
from typing import Any, Literal, NamedTuple

from claude_sentinel.command_normalizer import (
    drop_leading_runners,
    normalize_for_matching,
)


@dataclass
class Rule:
    name: str
    pattern: re.Pattern[str]
    path_globs: tuple[str, ...] = ()
    reason: str | None = None
    deny_if: str | None = None


@dataclass
class RuleSet:
    command_rules: list[Rule] = field(default_factory=list)
    sensitive_path_rules: list[Rule] = field(default_factory=list)


# Module-level cache
_deny_rules: RuleSet | None = None
_allow_rules: RuleSet | None = None
_ask_rules: RuleSet | None = None


def _parse_rules(data: dict[str, Any], *, kind: str) -> RuleSet:
    """Parse TOML data into a RuleSet.

    DENY rules are compiled with re.MULTILINE so the unparseable-command
    pre-filter catches `^\\s*sudo\\s+` etc. inside heredoc bodies, and so
    parsed segments containing multi-line content (e.g. ``bash -c '<body>'``)
    still trip line-anchored deny patterns. ASK and ALLOW rules use a plain
    anchor: a multi-line jq/awk/sed script in a single-quoted argument
    must not be interpreted line-by-line as bash commands.
    """
    ruleset = RuleSet()
    flags = re.MULTILINE if kind == "deny" else 0
    fragments = data.get("fragments", {})
    for entry in data.get("rules", []):
        ruleset.command_rules.append(
            Rule(
                name=entry["name"],
                pattern=re.compile(_expand_fragments(entry["command_regex"], fragments), flags),
                reason=entry.get("reason"),
                deny_if=entry.get("deny_if"),
            )
        )
    for entry in data.get("sensitive_path_rules", []):
        ruleset.sensitive_path_rules.append(
            Rule(
                name=entry["name"],
                pattern=re.compile(_expand_fragments(entry["path_regex"], fragments)),
                path_globs=tuple(entry.get("path_glob", [])),
            )
        )
    return ruleset


def _expand_fragments(regex: str, fragments: dict[str, str]) -> str:
    """Substitute ``@name@`` tokens with shared regex fragments.

    Plain string replacement rather than ``str.format`` so literal ``{n,m}``
    quantifiers in patterns are left untouched.
    """
    for name, value in fragments.items():
        regex = regex.replace(f"@{name}@", value)
    return regex


def sensitive_path_globs() -> list[str]:
    """Gitignore-style glob equivalents of the sensitive path rules."""
    return [glob for rule in get_deny_rules().sensitive_path_rules for glob in rule.path_globs]


def load_rules(path: str | None = None, *, kind: str = "deny") -> RuleSet:
    """Load rules from a TOML file. Uses importlib.resources for bundled rules."""
    if path:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    else:
        rules_pkg = resources.files("claude_sentinel.rules")
        filename = f"{kind}.toml"
        content = (rules_pkg / filename).read_text(encoding="utf-8")
        data = tomllib.loads(content)
    return _parse_rules(data, kind=kind)


def get_deny_rules() -> RuleSet:
    """Get cached deny rules."""
    global _deny_rules
    if _deny_rules is None:
        _deny_rules = load_rules(kind="deny")
    return _deny_rules


def get_allow_rules() -> RuleSet:
    """Get cached allow rules."""
    global _allow_rules
    if _allow_rules is None:
        _allow_rules = load_rules(kind="allow")
    return _allow_rules


def get_ask_rules() -> RuleSet:
    """Get cached ask rules."""
    global _ask_rules
    if _ask_rules is None:
        _ask_rules = load_rules(kind="ask")
    return _ask_rules


def _match_command_rules(rules: list[Rule], command: str) -> Rule | None:
    """Match a command against rules, trying the original form first and
    then a prefix-option-stripped form (so ``git -c http.proxy= push
    --force origin main`` still hits the ``force-push-main`` deny rule).
    The OR combination keeps matching safe: if either form matches, the
    rule applies.
    """
    normalized = normalize_for_matching(command)
    for rule in rules:
        if rule.pattern.search(command):
            return rule
        if normalized != command and rule.pattern.search(normalized):
            return rule
    return None


def match_deny(command: str) -> Rule | None:
    """Check if command matches any deny rule."""
    return _match_command_rules(get_deny_rules().command_rules, command)


def match_allow(command: str) -> Rule | None:
    """Check if command matches any allow rule."""
    return _match_command_rules(get_allow_rules().command_rules, command)


def match_ask(command: str) -> Rule | None:
    """Check if command matches any ask rule.

    Critical for safety: ``git -c safecrlf=false reset --hard`` must
    still match the ``git-reset-hard`` ask rule rather than falling
    through to LLM_JUDGE.
    """
    return _match_command_rules(get_ask_rules().command_rules, command)


def match_sensitive_path(file_path: str) -> Rule | None:
    """Check if file path matches any sensitive path deny rule."""
    normalized = file_path.replace("\\", "/")
    for rule in get_deny_rules().sensitive_path_rules:
        if rule.pattern.search(normalized):
            return rule
    return None


# `sed -i`/`--in-place` writes files directly. Unlike the Write/Edit tools,
# a bash command never passes through the sensitive_path_rules, so an in-place
# sed would otherwise be a backdoor around that protection while the generic
# `sed` allow rule waves it through. Reusing match_sensitive_path (rather than
# duplicating the path patterns here) keeps the two in sync: any path added to
# sensitive_path_rules is automatically off-limits to `sed -i` too.
_SED_INPLACE = re.compile(r"^\s*sed\s+(-[a-zA-Z]*i|--in-place)")


def match_inplace_write_sensitive(command: str) -> Rule | None:
    """Deny an in-place ``sed`` edit whose file argument is a sensitive path."""
    normalized = normalize_for_matching(command)
    if not (_SED_INPLACE.search(command) or _SED_INPLACE.search(normalized)):
        return None
    for token in command.split():
        hit = match_sensitive_path(token)
        if hit:
            return hit
    return None


def reset_cache() -> None:
    """Reset the rule cache (useful for testing)."""
    global _deny_rules, _allow_rules, _ask_rules
    _deny_rules = None
    _allow_rules = None
    _ask_rules = None
    _git_alias_discard.cache_clear()


# --- Bash command splitter ----------------------------------------------------
#
# A small, dependency-free splitter that walks a bash command string and
# returns the individual commands within it. We need just enough of bash's
# syntax to find command boundaries — we do NOT execute, expand, or even
# fully parse arbitrary bash. The grammar we recognise is:
#
#   * Operators that separate commands at the current scope:
#       && || ; | & newline
#     (single & is backgrounding, also a separator)
#   * Quoting: '...' (literal), "..." (with $() and `` live), \X (escape)
#   * Substitutions whose contents are themselves commands:
#       $(...)   command substitution
#       `...`    command substitution (backtick form)
#       <(...)   process substitution (read)
#       >(...)   process substitution (write)
#       (...)    subshell
#   * Parameter expansion ${...} (contents are NOT commands, but may
#     contain $(...) which IS a command)
#   * Redirections that include & as a fd reference: >&N, <&N, &>, &>>
#
# Anything we don't recognise (heredocs, ANSI-C $'...' quoting, control
# constructs like `case`, etc.) raises _ParseError, which the caller turns
# into a safe "ask" fallback. Missing-but-safe is the design: a parser bug
# can never silently ALLOW a dangerous command — at worst it forces an
# extra confirmation prompt.


class _ParseError(Exception):
    """Raised when the splitter encounters bash it cannot reason about."""


def _skip_ws(s: str, i: int, end: int) -> int:
    while i < end and s[i] in " \t":
        i += 1
    return i


def _skip_single_quote(s: str, i: int, end: int) -> int:
    """``i`` points at the opening ``'``. Returns position past the closing ``'``."""
    j = i + 1
    while j < end and s[j] != "'":
        j += 1
    if j >= end:
        raise _ParseError("unterminated single quote")
    return j + 1


def _skip_backtick(s: str, i: int, end: int) -> int:
    """``i`` points at opening `` ` ``. Returns position past closing `` ` ``."""
    j = i + 1
    while j < end and s[j] != "`":
        if s[j] == "\\" and j + 1 < end:
            j += 2
        else:
            j += 1
    if j >= end:
        raise _ParseError("unterminated backtick")
    return j + 1


def _skip_paren(s: str, i: int, end: int) -> int:
    """``i`` points at the opening ``(``. Returns position past the matching ``)``.

    Tracks quotes and nested constructs only enough to find the matching
    paren. Does NOT record substitutions for collection — the caller is
    expected to recursively process the inner span and discover them then.
    """
    depth = 1
    j = i + 1
    while j < end and depth > 0:
        c = s[j]
        if c == "'":
            j = _skip_single_quote(s, j, end)
        elif c == '"':
            j = _skip_double_quote(s, j, end, None)
        elif c == "`":
            j = _skip_backtick(s, j, end)
        elif c == "\\" and j + 1 < end:
            j += 2
        elif c == "$" and j + 1 < end and s[j + 1] == "(":
            j = _skip_paren(s, j + 1, end)
        elif c == "$" and j + 1 < end and s[j + 1] == "{":
            j = _skip_brace(s, j + 1, end, None)
        elif c == "(":
            depth += 1
            j += 1
        elif c == ")":
            depth -= 1
            j += 1
        else:
            j += 1
    if depth != 0:
        raise _ParseError("unbalanced (")
    return j


def _skip_double_quote(s: str, i: int, end: int, inner_subs: list[tuple[int, int]] | None) -> int:
    """``i`` points at the opening ``"``. Returns position past the closing ``"``.

    If ``inner_subs`` is given, any ``$(...)``, ``${...}``, or backtick
    substitution found directly inside the string contributes its inner
    span to the list (operators inside double-quoted strings are inert,
    but substitutions are live).
    """
    j = i + 1
    while j < end:
        c = s[j]
        if c == '"':
            return j + 1
        elif c == "\\" and j + 1 < end:
            j += 2
        elif c == "$" and j + 1 < end and s[j + 1] == "(":
            inner_start = j + 2
            j = _skip_paren(s, j + 1, end)
            if inner_subs is not None:
                inner_subs.append((inner_start, j - 1))
        elif c == "$" and j + 1 < end and s[j + 1] == "{":
            j = _skip_brace(s, j + 1, end, inner_subs)
        elif c == "`":
            inner_start = j + 1
            j = _skip_backtick(s, j, end)
            if inner_subs is not None:
                inner_subs.append((inner_start, j - 1))
        else:
            j += 1
    raise _ParseError("unterminated double quote")


def _skip_brace(s: str, i: int, end: int, inner_subs: list[tuple[int, int]] | None) -> int:
    """``i`` points at the opening ``{`` of a parameter expansion. Returns
    position past the matching ``}``. Records any substitutions inside.
    """
    depth = 1
    j = i + 1
    while j < end and depth > 0:
        c = s[j]
        if c == "\\" and j + 1 < end:
            j += 2
        elif c == "'":
            j = _skip_single_quote(s, j, end)
        elif c == '"':
            j = _skip_double_quote(s, j, end, inner_subs)
        elif c == "$" and j + 1 < end and s[j + 1] == "(":
            inner_start = j + 2
            j = _skip_paren(s, j + 1, end)
            if inner_subs is not None:
                inner_subs.append((inner_start, j - 1))
        elif c == "$" and j + 1 < end and s[j + 1] == "{":
            j = _skip_brace(s, j + 1, end, inner_subs)
        elif c == "`":
            inner_start = j + 1
            j = _skip_backtick(s, j, end)
            if inner_subs is not None:
                inner_subs.append((inner_start, j - 1))
        elif c == "{":
            depth += 1
            j += 1
        elif c == "}":
            depth -= 1
            j += 1
        else:
            j += 1
    if depth != 0:
        raise _ParseError("unbalanced {")
    return j


def _parse_heredoc_delim(s: str, i: int, end: int) -> tuple[str, bool, int]:
    """``i`` points at the first ``<`` of ``<<``. Returns ``(delimiter,
    tab_strip, position_past_delimiter_token)``.

    Recognizes ``<<DELIM``, ``<<-DELIM`` (tab-stripping form), and quoted
    delimiters ``<<'DELIM'`` / ``<<"DELIM"``.
    """
    j = i + 2
    tab_strip = False
    if j < end and s[j] == "-":
        tab_strip = True
        j += 1
    while j < end and s[j] in " \t":
        j += 1
    if j >= end:
        raise _ParseError("heredoc missing delimiter")

    if s[j] in ("'", '"'):
        quote = s[j]
        j += 1
        delim_start = j
        while j < end and s[j] != quote:
            if s[j] == "\\" and j + 1 < end:
                j += 2
            else:
                j += 1
        if j >= end:
            raise _ParseError("unterminated heredoc delimiter quote")
        delim = s[delim_start:j]
        j += 1  # consume closing quote
    else:
        delim_start = j
        while j < end and (s[j].isalnum() or s[j] == "_"):
            j += 1
        delim = s[delim_start:j]

    if not delim:
        raise _ParseError("empty heredoc delimiter")
    return delim, tab_strip, j


def _skip_heredoc_body(s: str, i: int, end: int, delim: str, tab_strip: bool) -> int:
    """``i`` points at the first char of the heredoc body (just after the
    newline that ended the command line containing ``<<DELIM``). Returns
    the position past the closing-delimiter line's terminating newline (or
    ``end`` if the file ends without one).
    """
    while i < end:
        line_start = i
        while i < end and s[i] != "\n":
            i += 1
        line = s[line_start:i]
        if tab_strip:
            line = line.lstrip("\t")
        if line == delim:
            if i < end:
                i += 1  # consume trailing \n
            return i
        if i < end:
            i += 1  # consume \n and keep scanning
    raise _ParseError(f"heredoc {delim!r} not closed")


def _split_range(s: str, start: int, end: int, all_segments: list[tuple[int, int]]) -> None:
    """Walk ``s[start:end]`` splitting on top-level command operators and
    appending each command's ``(start, end)`` span to ``all_segments``.
    Substitutions encountered are recursively processed so their inner
    commands are also collected.
    """
    inner_subs: list[tuple[int, int]] = []
    # Heredoc bodies follow the next newline after their ``<<DELIM`` marker,
    # so we queue declarations here and drain them when ``\n`` is reached.
    pending_heredocs: list[tuple[str, bool]] = []
    i = start
    cmd_start = _skip_ws(s, start, end)

    def emit(end_pos: int) -> None:
        e = end_pos
        while e > cmd_start and s[e - 1] in " \t":
            e -= 1
        if e > cmd_start:
            all_segments.append((cmd_start, e))

    while i < end:
        c = s[i]

        # --- Quoting ---
        if c == "'":
            i = _skip_single_quote(s, i, end)
            continue
        if c == '"':
            i = _skip_double_quote(s, i, end, inner_subs)
            continue
        if c == "`":
            inner_start = i + 1
            i = _skip_backtick(s, i, end)
            inner_subs.append((inner_start, i - 1))
            continue

        # --- Substitutions and groupings ---
        if c == "$" and i + 1 < end and s[i + 1] == "(":
            inner_start = i + 2
            i = _skip_paren(s, i + 1, end)
            inner_subs.append((inner_start, i - 1))
            continue
        if c == "$" and i + 1 < end and s[i + 1] == "{":
            i = _skip_brace(s, i + 1, end, inner_subs)
            continue
        if c == "$" and i + 1 < end and s[i + 1] == "'":
            # ANSI-C quoting $'...' has its own escape rules we don't model.
            raise _ParseError("$'...' ANSI-C quoting not supported")
        if c == "(":
            at_command_start = _skip_ws(s, cmd_start, i) == i
            inner_start = i + 1
            i = _skip_paren(s, i, end)
            inner_subs.append((inner_start, i - 1))
            if at_command_start:
                # A command-position subshell isn't a command itself; its body
                # is collected above for recursion. Drop the ``(...)`` wrapper
                # from the emitted segment (it matches no rule, forcing a
                # needless LLM fallback) while leaving any trailing redirection
                # as its own segment so deny rules still see it.
                cmd_start = i
            continue

        # A command-position ``{ …; }`` brace group. Bash requires whitespace
        # after the brace, which distinguishes it from ``${…}`` (handled above)
        # and literals like ``find … {} +``. Same treatment as a subshell:
        # unwrap to the inner commands, keep any trailing redirection.
        if c == "{" and _skip_ws(s, cmd_start, i) == i and i + 1 < end and s[i + 1] in " \t\n":
            inner_start = i + 1
            i = _skip_brace(s, i, end, None)
            inner_subs.append((inner_start, i - 1))
            cmd_start = i
            continue

        # --- Heredocs and here-strings ---
        if c == "<" and i + 1 < end and s[i + 1] == "<":
            if i + 2 < end and s[i + 2] == "<":
                # ``<<<`` here-string: the value is a normal token, skip the op.
                i += 3
                continue
            delim, tab_strip, i = _parse_heredoc_delim(s, i, end)
            pending_heredocs.append((delim, tab_strip))
            continue

        # --- Process substitution <(...) and >(...) ---
        if c in "<>" and i + 1 < end and s[i + 1] == "(":
            inner_start = i + 2
            i = _skip_paren(s, i + 1, end)
            inner_subs.append((inner_start, i - 1))
            continue

        # --- Plain redirections (>file, <file, 2>&1, &>file, &>>file) ---
        if c in "<>":
            i += 1
            # Append-form >> or fd-duplication >&N / <&N
            if i < end and s[i] in "<>&":
                i += 1
            continue

        # --- Escapes ---
        if c == "\\" and i + 1 < end:
            i += 2
            continue

        # --- Operators that separate commands ---
        if c == "&":
            if i + 1 < end and s[i + 1] == "&":
                emit(i)
                i += 2
                cmd_start = _skip_ws(s, i, end)
                continue
            if i + 1 < end and s[i + 1] == ">":
                # &> or &>> redirect (bash shorthand for >file 2>&1)
                i += 2
                if i < end and s[i] == ">":
                    i += 1
                continue
            # bare & — backgrounding, acts as a separator
            emit(i)
            i += 1
            cmd_start = _skip_ws(s, i, end)
            continue

        if c == "|":
            if i + 1 < end and s[i + 1] == "|":
                emit(i)
                i += 2
                cmd_start = _skip_ws(s, i, end)
                continue
            # |& is a pipe that also dup's stderr — same separator semantics
            emit(i)
            i += 1
            if i < end and s[i] == "&":
                i += 1
            cmd_start = _skip_ws(s, i, end)
            continue

        if c == ";":
            # ;; is a case terminator we don't support
            if i + 1 < end and s[i + 1] == ";":
                raise _ParseError(";; (case terminator) not supported")
            emit(i)
            i += 1
            cmd_start = _skip_ws(s, i, end)
            continue

        if c == "\n":
            if pending_heredocs:
                # Heredoc body+closing-delim are absorbed into the current
                # segment so MULTILINE deny rules still see body content.
                i += 1
                while pending_heredocs:
                    delim, tab_strip = pending_heredocs.pop(0)
                    i = _skip_heredoc_body(s, i, end, delim, tab_strip)
                emit(i)
                cmd_start = _skip_ws(s, i, end)
                continue
            emit(i)
            i += 1
            cmd_start = _skip_ws(s, i, end)
            continue

        # --- Anything else: ordinary command character ---
        i += 1

    if pending_heredocs:
        raise _ParseError("unterminated heredoc at end of input")
    emit(end)

    # Recurse into substitution bodies — but only spans with content.
    # Each recursive call will discover its own nested substitutions.
    for a, b in inner_subs:
        if a < b:
            _split_range(s, a, b, all_segments)


# Constructs that run a STRING argument as an inline script. The char splitter
# treats that argument as one opaque quoted token, so without this the whole
# `bash -c "..."` / `eval "..."` is a single segment that matches a permissive
# allow rule — hiding whatever the script does (a loop, a mutation) from the
# start-anchored rules. We dequote the script and evaluate its commands too.
_SHELL_C_RUNNERS: frozenset[str] = frozenset({"bash", "sh", "zsh", "dash", "ash", "ksh"})
# A short-flag group ending in `c` (`-c`, `-lc`, `-euc`) introduces the script;
# one ending in `o` (`-o`, `-euo`) consumes the next token as its value
# (`-o pipefail`), so that value must be skipped, not treated as the command.
_DASH_C_FLAG = re.compile(r"[-+][a-zA-Z]*c")
_DASH_O_FLAG = re.compile(r"[-+][a-zA-Z]*o")


def _tokenize_segment(segment: str) -> list[str]:
    """Shell-split a segment and drop leading wrapper/runner prefixes, returning
    ``[]`` when it cannot be dequoted."""
    try:
        return drop_leading_runners(shlex.split(segment, posix=True))
    except ValueError:
        return []


def _extract_inline_script(segment: str) -> str | None:
    """Return the inline script from a ``<shell> [opts] -c <script>`` or
    ``eval <script>`` segment, else ``None``.

    Leading wrapper/runner prefixes (``exec``/``nohup``/``env``/``timeout`` …)
    are stripped first, so ``exec bash -c '...'`` and ``timeout 5 bash -c '...'``
    are still unwrapped. Returns ``None`` when the segment is not such a form or
    cannot be dequoted.
    """
    tokens = _tokenize_segment(segment)
    if not tokens:
        return None
    if tokens[0] == "eval" and len(tokens) >= 2:
        return " ".join(tokens[1:])
    if len(tokens) < 3 or tokens[0] not in _SHELL_C_RUNNERS:
        return None
    idx = 1
    while idx < len(tokens):
        tok = tokens[idx]
        if not tok.startswith(("-", "+")):
            return None  # command/script-file word reached before any -c
        if _DASH_C_FLAG.fullmatch(tok):
            return tokens[idx + 1] if idx + 1 < len(tokens) else None
        if _DASH_O_FLAG.fullmatch(tok):
            idx += 2  # e.g. -o pipefail / -euo pipefail — skip the value
            continue
        idx += 1
    return None


def extract_commands(command: str) -> list[str] | None:
    """Split a bash command into the individual commands it would execute.

    Returns:
        * ``[]`` if the input is empty/whitespace.
        * ``None`` if the input is malformed or uses unsupported syntax
          (caller resolves this to a safe "ask" decision).
        * Otherwise, a list of command strings — one for every simple
          command found at any nesting level (top-level, inside
          ``$(...)`` / `` `...` `` / ``<(...)`` / ``(...)`` subshells, and
          inside double-quoted strings or ``${...}`` parameter expansion).

    Each returned segment is sliced from the original input so quoting
    and redirections are preserved exactly as written, which is what the
    existing per-command regex rules expect.
    """
    if not command.strip():
        return []
    try:
        spans: list[tuple[int, int]] = []
        _split_range(command, 0, len(command), spans)
    except _ParseError:
        return None

    seen: set[tuple[int, int]] = set()
    out: list[str] = []
    for a, b in spans:
        if (a, b) in seen:
            continue
        seen.add((a, b))
        out.append(command[a:b])

    # Recurse into `bash -c <script>` / `eval <script>` inline scripts so their
    # commands face the same rules. If an inner script is itself unparseable, we
    # must not let the opaque wrapper segment be auto-allowed — treat the whole
    # command as unparseable so it goes through the deny prefilter and the LLM.
    for segment in list(out):
        script = _extract_inline_script(segment)
        if script is None:
            continue
        inner = extract_commands(script)
        if inner is None:
            return None
        out.extend(inner)
    return out


# Interpreters that run arbitrary code and so must be intercepted before the
# broad allow rules. node/python/bash/sh/zsh are otherwise blanket-allowed by
# node-run/python-run/zsh-run; ruby/perl/dash/ksh/ash have no allow rule and are
# escalated only to upgrade an out-of-project script from the plain judge to the
# read judge. deno/bun are excluded: their subcommand grammar (``deno run
# <file>`` / ``bun run <script-name>``) doesn't fit the ``<interp> [opts]
# <file>`` model a reader would otherwise expect them to.
_SCRIPT_INTERPRETERS: frozenset[str] = frozenset(
    {"node", "python", "python3", "ruby", "perl", "bash", "sh", "zsh", "dash", "ksh", "ash"}
)

# Flags that make an interpreter run inline code from the command string rather
# than a file. The code is visible to the judge in the command text, so these
# route to the plain LLM judge rather than the read judge. Shells are absent:
# their ``-c`` inline form is unwrapped and re-evaluated upstream by
# ``extract_commands`` (see ``_SHELL_C_RUNNERS``).
_INLINE_EVAL_FLAGS: dict[str, frozenset[str]] = {
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "python": frozenset({"-c"}),
    "python3": frozenset({"-c"}),
    "ruby": frozenset({"-e"}),
    "perl": frozenset({"-e", "-E"}),
}


def _has_inline_flag(args: list[str], inline_flags: frozenset[str]) -> bool:
    """True if any arg is an inline-eval flag, including the glued short form
    (``-ecode``) and the ``=``-attached long form (``--eval=code``). Matching the
    bare split token alone would miss ``node -e'code'`` / ``python -c'code'`` and
    let the inline code reach the permissive interpreter allow rule."""
    for arg in args:
        for flag in inline_flags:
            if flag.startswith("--"):
                if arg == flag or arg.startswith(flag + "="):
                    return True
            elif arg.startswith(flag):
                return True
    return False


def _interpreter_escalation(segment: str, cwd: str) -> tuple[str | None, list[str]]:
    """Classify an interpreter invocation that must escalate past the broad
    ``node-run`` / ``python-run`` / ``zsh-run`` allow rules.

    Returns ``(kind, outside_paths)`` where kind is:
        * ``"llm"``      — inline code execution (``node -e``, ``python -c`` …).
        * ``"llm_read"`` — runs a script FILE outside ``cwd``; ``outside_paths``
          holds the resolved paths so the caller can grant the judge read access.
        * ``None``       — not an escalating interpreter invocation (in-project
          script, REPL, ``python -m`` …); defer to the normal allow rules.
    """
    tokens = _tokenize_segment(segment)
    if not tokens:
        return None, []
    head = os.path.basename(tokens[0])
    if head not in _SCRIPT_INTERPRETERS:
        return None, []

    args = tokens[1:]
    if _has_inline_flag(args, _INLINE_EVAL_FLAGS.get(head, frozenset())):
        return "llm", []
    # A shell ``-c '<script>'`` is inline code, already unwrapped and re-evaluated
    # by ``extract_commands``; its value is not a script file to read.
    if head in _SHELL_C_RUNNERS and any(_DASH_C_FLAG.fullmatch(a) for a in args):
        return None, []

    outside = _out_of_project_scripts(args, cwd)
    if outside:
        return "llm_read", outside
    return None, []


def _out_of_project_scripts(args: list[str], cwd: str) -> list[str]:
    """Resolved paths, among an interpreter's non-flag ``args``, that live outside
    ``cwd``. Every non-flag argument is checked (not just the first positional):
    a script can follow a value-taking flag, as in ``node -r preload.js app.js``
    or ``python -W ignore ../outside/evil.py``, so restricting to the first
    positional would miss it. In-project arguments resolve inside ``cwd`` and are
    not flagged, so ordinary data-file arguments do not escalate.
    """
    base = os.path.expanduser(cwd)
    root = os.path.realpath(base)
    outside: list[str] = []
    for arg in args:
        if arg.startswith("-"):
            continue
        resolved = _resolve_path(arg, base)
        if not _is_within(resolved, root):
            outside.append(resolved)
    return outside


def _resolve_path(path: str, base: str) -> str:
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded):
        expanded = os.path.join(base, expanded)
    return os.path.realpath(expanded)


def _is_within(target: str, root: str) -> bool:
    """True when realpath ``target`` is ``root`` or below it."""
    try:
        return os.path.commonpath([root, target]) == root
    except ValueError:
        # Uncomparable roots (different drives): treat as outside (safe).
        return False


@cache
def _git_alias_discard(cwd: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "config", "--get", "alias.discard"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and bool(result.stdout.strip())


def _ask_or_deny(rule: Rule, cwd: str) -> Literal["ask", "deny"]:
    """Verdict for a matched ASK rule.

    A rule carrying ``deny_if`` escalates to DENY only where the replacement its
    ``reason`` names exists, so a blocked command is never left without an
    alternative.
    """
    if rule.deny_if == "git-alias-discard" and _git_alias_discard(cwd):
        return "deny"
    return "ask"


def _evaluate_segment(segment: str, cwd: str) -> tuple[str, Rule | None, list[str]]:
    """Evaluate a single segment through DENY -> ASK -> interpreter escalation
    -> ALLOW.

    Returns (decision, matched_rule, read_paths) where decision is one of
    'deny', 'ask', 'llm', 'llm_read', 'allow', 'unmatched'. ``read_paths`` holds
    the out-of-project script paths to grant read access to; it is non-empty only
    for 'llm_read'.

    The interpreter escalation runs before ALLOW so that inline code
    (``node -e``) and out-of-project script files (``bash /tmp/x.sh``) are not
    swallowed by the permissive ``node-run`` / ``zsh-run`` allow rules.
    """
    deny = match_deny(segment) or match_inplace_write_sensitive(segment)
    if deny:
        return "deny", deny, []
    ask = match_ask(segment)
    if ask:
        return _ask_or_deny(ask, cwd), ask, []
    kind, paths = _interpreter_escalation(segment, cwd)
    if kind is not None:
        return kind, None, paths
    allow = match_allow(segment)
    if allow:
        return "allow", allow, []
    return "unmatched", None, []


Decision = Literal["deny", "ask", "allow", "llm", "llm_read"]


class BashEvaluation(NamedTuple):
    """Full result of evaluating a bash command.

    ``read_dirs`` is populated only when ``decision`` is ``"llm_read"``: the
    directories the LLM judge must be granted read access to (``add_dirs``) so it
    can inspect the out-of-project script files the command executes.
    """

    decision: Decision
    reason: str
    read_dirs: tuple[str, ...] = ()


def _deny_reason(rule: Rule) -> str:
    """Deny reason surfaced to Claude, with the rule's guidance appended.

    A rule's optional ``reason`` redirects Claude to the native alternative
    (subagent completion notification, run_in_background, KillShell/TaskStop,
    the recoverable equivalent an escalated ask rule names) so a reason-less
    block does not push it toward a bypass.
    """
    base = f"Blocked by deny rule: {rule.name}"
    return f"{base}. {rule.reason}" if rule.reason else base


def evaluate_bash_command(command: str, cwd: str | None = None) -> BashEvaluation:
    """Evaluate a bash command by splitting it into segments and applying
    DENY -> ASK -> interpreter escalation -> ALLOW to each segment with
    strictest-wins aggregation.

    Decision precedence (most-restrictive wins):
        deny > ask > llm_read > llm > allow

    ``cwd`` is the working directory the command runs in; it decides whether an
    interpreter's script-file argument is inside the project (allow) or outside
    it (``llm_read``). Defaults to ``os.getcwd()`` when not supplied.

    For ``llm``/``llm_read`` the caller invokes the LLM judge with the original
    full command; ``llm_read`` additionally carries ``read_dirs`` so the judge can
    be granted read access to the out-of-project script files.
    """
    if cwd is None:
        cwd = os.getcwd()
    segments = extract_commands(command)
    if segments is None:
        # Defense-in-depth scan over the full string before LLM fallback.
        # Both DENY and ASK rules are anchored at ``^\s*<head>`` so they
        # only match when the unparseable command's head is the rule's
        # expected program.
        deny = match_deny(command) or match_inplace_write_sensitive(command)
        if deny:
            return BashEvaluation("deny", _deny_reason(deny))
        ask = match_ask(command)
        if ask:
            if _ask_or_deny(ask, cwd) == "deny":
                return BashEvaluation("deny", _deny_reason(ask))
            return BashEvaluation("ask", f"Matched ask rule: {ask.name}")
        return BashEvaluation("llm", "Unparseable bash; deferring to LLM judge")
    if not segments:
        return BashEvaluation("allow", "Empty command")

    deny_hit: Rule | None = None
    ask_hit: Rule | None = None
    has_unmatched = False
    read_dirs: list[str] = []
    seen_dirs: set[str] = set()
    allow_names: list[str] = []
    seen_allow: set[str] = set()

    for segment in segments:
        decision, rule, read_paths = _evaluate_segment(segment, cwd)
        if decision == "deny":
            assert rule is not None
            if deny_hit is None:
                deny_hit = rule
        elif decision == "ask":
            assert rule is not None
            if ask_hit is None:
                ask_hit = rule
        elif decision == "llm_read":
            for parent in (os.path.dirname(p) for p in read_paths):
                if parent and parent not in seen_dirs:
                    seen_dirs.add(parent)
                    read_dirs.append(parent)
        elif decision == "allow":
            assert rule is not None
            if rule.name not in seen_allow:
                seen_allow.add(rule.name)
                allow_names.append(rule.name)
        else:
            # "llm" (inline eval) and "unmatched" both defer to the plain judge.
            has_unmatched = True

    if deny_hit is not None:
        return BashEvaluation("deny", _deny_reason(deny_hit))
    if ask_hit is not None:
        return BashEvaluation("ask", f"Matched ask rule: {ask_hit.name}")
    if read_dirs:
        return BashEvaluation(
            "llm_read",
            "Out-of-project script; deferring to LLM judge with file read",
            tuple(read_dirs),
        )
    if has_unmatched:
        return BashEvaluation("llm", "No rule matched; deferring to LLM judge")
    return BashEvaluation("allow", f"Allowed by rules: {', '.join(allow_names)}")


def evaluate_command(command: str, cwd: str | None = None) -> tuple[Decision, str]:
    """Decision facade over :func:`evaluate_bash_command` for callers that need
    only the (decision, reason) verdict, not the judge's read-access dirs."""
    result = evaluate_bash_command(command, cwd)
    return result.decision, result.reason
