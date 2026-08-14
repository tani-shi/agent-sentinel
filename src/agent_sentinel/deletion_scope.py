"""Verdicts for a recursive ``rm`` based on where its targets point.

A scratch directory under a temp root and a tracked source tree are both reached
by ``rm -rf``, and a single ask rule cannot tell them apart: the targets are
often written as ``$S`` and the rules match one segment at a time. Resolving the
targets — through the literal assignments earlier in the same command line —
turns the one rule into a scoped verdict, so scratch work runs unprompted while
files git tracks are pushed toward a recoverable deletion.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator, Mapping
from functools import cache
from typing import Literal, NamedTuple

from agent_sentinel import git_probe, paths
from agent_sentinel.command_normalizer import path_arguments, tokenize

_RECURSIVE_SHORT_FLAG = re.compile(r"^-[a-zA-Z]*[rR][a-zA-Z]*$")
# Characters the shell expands into path names `rm` never receives verbatim.
# Braces belong here with the glob metacharacters: `rm -rf {src,tests}` reaches
# two paths, neither of them the word written on the command line.
_EXPANSION_CHARS = re.compile(r"[*?\[{]")
_VARIABLE_REFERENCE = re.compile(r"\$\{(\w+)\}|\$(\w+)")
_UNRESOLVED = re.compile(r"[$`]")
# `S=$T` chains resolve in a few passes; a self-referential assignment never
# does, and an expansion that is still unresolved falls through to asking.
_MAX_EXPANSION_PASSES = 4
_TMPDIR = "TMPDIR"
# The variables read from the hook's own environment, which is the shell's: a
# command writes `$TMPDIR` and `$HOME` as often as the literal path, and both
# name a tree whose verdict the scope already has.
_ENVIRONMENT_NAMES = (_TMPDIR, "HOME")


# Literal assignments the targets are resolved through: the same form the
# ``variable-assignment`` allow rule accepts, which excludes command substitution
# and further variable references.
_LITERAL_ASSIGNMENT = re.compile(
    r"""^\s*([A-Za-z_][A-Za-z0-9_]*)=('[^']*'|"[^"`$]*"|[\w./:@%+-]*)\s*$"""
)


class Assignments(Mapping[str, str]):
    """The variable values a command line's segments assign, accumulated in the
    order the segments are read, for :func:`classify` to resolve targets through.

    Which of two assignments to the same name runs depends on the operator
    between them (``S=/etc/x || S=/tmp/x``), which the splitter does not report.
    A contested name resolves to nothing at all — not even a later agreeing
    assignment revives it.
    """

    def __init__(self) -> None:
        self._values: dict[str, str] = {}
        self._contested: set[str] = set()

    def record(self, segment: str) -> None:
        """Record what a bare literal-assignment segment assigns; other segments
        assign nothing."""
        match = _LITERAL_ASSIGNMENT.match(segment)
        if match is None:
            return
        name, value = match.group(1), match.group(2).strip("'\"")
        if self._values.get(name, value) != value:
            self._contested.add(name)
            del self._values[name]
        elif name not in self._contested:
            self._values[name] = value

    def __getitem__(self, name: str) -> str:
        return self._values[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


class Verdict(NamedTuple):
    """A scope decision for a whole ``rm`` segment. ``name`` reaches the log and
    the user as the rule name; ``reason`` carries the deny guidance."""

    decision: Literal["deny", "allow"]
    name: str
    reason: str | None = None


_TEMP_SCOPE = Verdict("allow", "rm-temp-scope")
_IGNORED_PATH = Verdict("allow", "rm-ignored-path")
_MISSING_PATH = Verdict("allow", "rm-missing-path")

_TEMP_ROOT = Verdict(
    "deny",
    "rm-temp-root",
    "Wipes the temp root every process on the machine shares. Delete the "
    "specific directory the command created under it — not the root itself.",
)
_ROOT_TARGET = Verdict(
    "deny",
    "rm-root-target",
    "Wipes the whole filesystem or the whole home directory. Name the specific "
    "directory to remove — not / or the home directory itself.",
)
_TRACKED_PATH = Verdict(
    "deny",
    "rm-tracked-path",
    "Deletes files git tracks, along with any uncommitted change in them. Stage "
    "the deletion with `git rm -r <path>`, which leaves the content in HEAD to "
    "restore from — not rm -rf.",
)
_UNTRACKED_PATH = Verdict(
    "deny",
    "rm-untracked-path",
    "Deletes untracked files, which no commit can restore. Use `git discard "
    "--untracked <path>`: it snapshots to refs/discard/* first, so `git discard "
    "--undo` brings the files back — not rm -rf.",
)


def classify(segment: str, cwd: str, assignments: Mapping[str, str]) -> Verdict | None:
    """Scope verdict for a recursive ``rm`` segment, or ``None`` when the scope
    does not decide it — a non-recursive or non-``rm`` segment, an unresolved
    target, or a target outside both the temp roots and the working directory.
    ``None`` leaves the segment to the ordinary rules, where the ``rm-recursive``
    ask rule waits.

    ``assignments`` maps variable names to the literal values assigned earlier in
    the same command line.
    """
    tokens = tokenize(segment)
    if not tokens or os.path.basename(tokens[0]) != "rm":
        return None
    words = [_expand(word, assignments) for word in path_arguments(tokens[1:])]
    if not words or not _is_recursive(tokens[1:]):
        return None

    first_allowed: Verdict | None = None
    for word in words:
        verdict = _classify_target(word, cwd)
        if verdict is None:
            return None
        if verdict.decision == "deny":
            return verdict
        first_allowed = first_allowed or verdict
    return first_allowed


def _is_recursive(args: list[str]) -> bool:
    literal = False
    for arg in args:
        if arg == "--":
            literal = True
        elif not literal and (arg == "--recursive" or _RECURSIVE_SHORT_FLAG.match(arg)):
            return True
    return False


def _expand(word: str, assignments: Mapping[str, str]) -> str:
    """Substitute the variable references whose values are known. A reference
    with no known value is left as written, for the caller to decline."""

    def value_of(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        if name in assignments:
            return assignments[name]
        if name in _ENVIRONMENT_NAMES:
            return os.environ.get(name) or match.group(0)
        return match.group(0)

    for _ in range(_MAX_EXPANSION_PASSES):
        expanded = _VARIABLE_REFERENCE.sub(value_of, word)
        if expanded == word:
            break
        word = expanded
    return word


def _classify_target(word: str, cwd: str) -> Verdict | None:
    if _UNRESOLVED.search(word):
        return None
    resolved = paths.resolve(word, cwd)
    if _is_home_or_filesystem_root(resolved):
        return _ROOT_TARGET

    root = _temp_root_of(resolved)
    if root is not None:
        return _classify_temp_target(resolved, root)
    if _EXPANSION_CHARS.search(resolved):
        return None
    if not paths.is_within(resolved, os.path.realpath(cwd)):
        return None
    if not os.path.lexists(resolved):
        # Nothing to delete. Without this, `rm -rf build && mkdir build` would
        # ask on every project whose build directory is not there yet.
        return _MISSING_PATH
    return _classify_project_target(resolved, cwd)


def _is_home_or_filesystem_root(resolved: str) -> bool:
    """True for the two targets no flag or quoting may talk past. The
    ``rm-rf-root`` deny rule reads the raw command line, where a flag between the
    recursive flag and the target (``rm -rf --no-preserve-root /``) or a quoted
    ``"$HOME"`` slips by it; the resolved target does not hide either form."""
    if resolved == os.sep:
        return True
    home = os.path.expanduser("~")
    return os.path.isabs(home) and resolved == os.path.realpath(home)


def _classify_temp_target(resolved: str, root: str) -> Verdict | None:
    """A path under a temp root is expendable, except for the root itself —
    which ``<root>/*`` also stands for, since the shell expands it to every
    entry other processes left there. A partial pattern (``<root>/sess-*``) is
    left undecided: it reaches an unknown set of siblings, but not the root."""
    if resolved == root:
        return _TEMP_ROOT
    if not _expands_at_root_level(resolved, root):
        return _TEMP_SCOPE
    return _TEMP_ROOT if os.path.relpath(resolved, root) == "*" else None


def _classify_project_target(resolved: str, cwd: str) -> Verdict | None:
    if not git_probe.in_repository(cwd):
        return None
    tracked = git_probe.tracks(cwd, resolved)
    if tracked is None:
        return None
    if tracked:
        return _TRACKED_PATH
    ignored = git_probe.ignores(cwd, resolved)
    if ignored is None:
        return None
    if ignored:
        return _IGNORED_PATH
    return _UNTRACKED_PATH if git_probe.has_discard_alias(cwd) else None


def _expands_at_root_level(resolved: str, root: str) -> bool:
    """True when the shell expands the component naming the root's own child, so
    the pattern reaches an unknown set of the root's entries."""
    child = os.path.relpath(resolved, root).split(os.sep)[0]
    return _EXPANSION_CHARS.search(child) is not None


@cache
def _temp_roots() -> tuple[str, ...]:
    """The temp roots a deletion may target freely. ``$TMPDIR`` is read from the
    hook's own environment, which is the shell's: the value a command would
    expand is the value admitted here."""
    roots: list[str] = []
    for candidate in ("/tmp", "/private/tmp", "/var/tmp", os.environ.get(_TMPDIR, "")):
        if not candidate or not os.path.isabs(candidate):
            continue
        root = os.path.realpath(candidate)
        if root != os.sep and root not in roots:
            roots.append(root)
    return tuple(roots)


def _temp_root_of(resolved: str) -> str | None:
    """The innermost temp root containing ``resolved``. Longest wins: a
    ``$TMPDIR`` nested under ``/private/tmp`` is a root in its own right, not a
    directory inside the enclosing one."""
    return max(
        (root for root in _temp_roots() if paths.is_within(resolved, root)),
        key=len,
        default=None,
    )


def reset_temp_roots() -> None:
    """Forget the resolved temp roots (useful for testing)."""
    _temp_roots.cache_clear()
