"""Read-only git questions about a working directory and the paths inside it.

The deletion scope asks what git already knows about an ``rm`` target; the
``deny_if`` escalation asks whether ``git discard`` exists. Neither owns the
answers, so they live here.
"""

from __future__ import annotations

import subprocess
from functools import cache

# The probe runs inside the PreToolUse hook, ahead of the user's own command. A
# repository on a stalled network mount must not hold the hook open, so a probe
# that misses its window is treated like any other unknown and the caller falls
# back to asking.
_GIT_TIMEOUT = 1.0


def in_repository(cwd: str) -> bool:
    return _answers(cwd, "rev-parse", "--show-toplevel")


def has_discard_alias(cwd: str) -> bool:
    """True where ``git discard`` exists — the recoverable way to remove files
    git knows about, and the replacement the escalated ask rules name. Absent, a
    command that would be blocked stays a question for the user instead."""
    return _answers(cwd, "config", "--get", "alias.discard")


def tracks(cwd: str, path: str) -> bool | None:
    """Whether git tracks ``path`` or anything under it, or ``None`` when git
    declines to answer. A declined answer must not read as ``False``: git prints
    nothing for an untracked path too, so the caller would take a probe that
    never ran for evidence that the path is expendable."""
    result = _git(cwd, "ls-files", "-z", "--", path)
    if result is None or result.returncode != 0:
        return None
    return bool(result.stdout)


def ignores(cwd: str, path: str) -> bool | None:
    """Whether ``path`` matches an ignore rule, or ``None`` when git declines to
    answer (exit codes other than the documented 0 match / 1 no match)."""
    result = _git(cwd, "check-ignore", "-q", "--", path)
    if result is None or result.returncode not in (0, 1):
        return None
    return result.returncode == 0


@cache
def _answers(cwd: str, *args: str) -> bool:
    """Whether a git query exits 0 and prints something, remembered per working
    directory. An empty answer is no answer: ``config --get`` exits 0 for a key
    set to the empty string, and ``rev-parse --show-toplevel`` prints nothing
    outside a working tree. A probe whose emptiness means the opposite — a ``-q``
    form such as ``check-ignore`` — must not be routed through here."""
    result = _git(cwd, *args)
    return result is not None and result.returncode == 0 and bool(result.stdout.strip())


def _git(cwd: str, *args: str) -> subprocess.CompletedProcess[str] | None:
    """Run a git query, or ``None`` when it cannot be answered."""
    try:
        return subprocess.run(
            ["git", "-C", cwd, *args],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def reset_probes() -> None:
    """Forget the remembered probe answers (useful for testing)."""
    _answers.cache_clear()
