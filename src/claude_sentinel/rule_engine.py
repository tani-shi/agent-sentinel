"""TOML rule loading and regex matching."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, Literal

from claude_sentinel.command_normalizer import normalize_for_matching


@dataclass
class Rule:
    name: str
    pattern: re.Pattern[str]


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
    for entry in data.get("rules", []):
        ruleset.command_rules.append(
            Rule(
                name=entry["name"],
                pattern=re.compile(entry["command_regex"], flags),
            )
        )
    for entry in data.get("sensitive_path_rules", []):
        ruleset.sensitive_path_rules.append(
            Rule(name=entry["name"], pattern=re.compile(entry["path_regex"]))
        )
    return ruleset


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


def match_deny(command: str) -> Rule | None:
    """Check if command matches any deny rule.

    Tries the original command first, then a prefix-option-stripped form
    (so ``git -c http.proxy= push --force origin main`` still hits the
    ``force-push-main`` deny rule). The OR combination keeps deny safe:
    if either form matches, the command is denied.
    """
    normalized = normalize_for_matching(command)
    for rule in get_deny_rules().command_rules:
        if rule.pattern.search(command):
            return rule
        if normalized != command and rule.pattern.search(normalized):
            return rule
    return None


def match_allow(command: str) -> Rule | None:
    """Check if command matches any allow rule.

    Falls back to the prefix-option-stripped form so ``git -c x=y diff``
    matches the same allow rule as ``git diff``.
    """
    normalized = normalize_for_matching(command)
    for rule in get_allow_rules().command_rules:
        if rule.pattern.search(command):
            return rule
        if normalized != command and rule.pattern.search(normalized):
            return rule
    return None


def match_ask(command: str) -> Rule | None:
    """Check if command matches any ask rule.

    Critical for safety: ``git -c safecrlf=false reset --hard`` must
    still match the ``git-reset-hard`` ask rule rather than falling
    through to LLM_JUDGE.
    """
    normalized = normalize_for_matching(command)
    for rule in get_ask_rules().command_rules:
        if rule.pattern.search(command):
            return rule
        if normalized != command and rule.pattern.search(normalized):
            return rule
    return None


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
    return out


def _evaluate_segment(segment: str) -> tuple[str, Rule | None]:
    """Evaluate a single segment through DENY -> ASK -> ALLOW.

    Returns (decision, matched_rule) where decision is one of
    'deny', 'ask', 'allow', 'unmatched'.
    """
    deny = match_deny(segment) or match_inplace_write_sensitive(segment)
    if deny:
        return "deny", deny
    ask = match_ask(segment)
    if ask:
        return "ask", ask
    allow = match_allow(segment)
    if allow:
        return "allow", allow
    return "unmatched", None


def evaluate_command(
    command: str,
) -> tuple[Literal["deny", "ask", "allow", "llm"], str]:
    """Evaluate a bash command by splitting it into segments and applying
    DENY -> ASK -> ALLOW to each segment with strictest-wins aggregation.

    Decision precedence (most-restrictive wins):
        deny > ask > llm > allow

    Returns (decision, reason). The reason is a human-readable string
    suitable for logging. When decision is 'llm', the caller should invoke
    the LLM judge with the original full command (not any segment).
    """
    segments = extract_commands(command)
    if segments is None:
        # Defense-in-depth scan over the full string before LLM fallback.
        # Both DENY and ASK rules are anchored at ``^\s*<head>`` so they
        # only match when the unparseable command's head is the rule's
        # expected program.
        deny = match_deny(command) or match_inplace_write_sensitive(command)
        if deny:
            return "deny", f"Blocked by deny rule: {deny.name}"
        ask = match_ask(command)
        if ask:
            return "ask", f"Matched ask rule: {ask.name}"
        return "llm", "Unparseable bash; deferring to LLM judge"
    if not segments:
        return "allow", "Empty command"

    deny_hit: Rule | None = None
    ask_hit: Rule | None = None
    has_unmatched = False
    allow_names: list[str] = []
    seen_allow: set[str] = set()

    for segment in segments:
        decision, rule = _evaluate_segment(segment)
        if decision == "deny":
            assert rule is not None
            if deny_hit is None:
                deny_hit = rule
        elif decision == "ask":
            assert rule is not None
            if ask_hit is None:
                ask_hit = rule
        elif decision == "allow":
            assert rule is not None
            if rule.name not in seen_allow:
                seen_allow.add(rule.name)
                allow_names.append(rule.name)
        else:
            has_unmatched = True

    if deny_hit is not None:
        return "deny", f"Blocked by deny rule: {deny_hit.name}"
    if ask_hit is not None:
        return "ask", f"Matched ask rule: {ask_hit.name}"
    if has_unmatched:
        return "llm", "No rule matched; deferring to LLM judge"
    return "allow", f"Allowed by rules: {', '.join(allow_names)}"
