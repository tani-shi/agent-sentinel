"""Resolution and containment tests for path arguments found in a command.

Both the interpreter escalation (is this script inside the project?) and the
deletion scope (is this rm target inside a temp root?) turn a command-line word
into an absolute path and ask which tree it belongs to.
"""

from __future__ import annotations

import os


def resolve(path: str, cwd: str) -> str:
    """Absolute, symlink-resolved form of a command-line path argument, taking a
    relative one from ``cwd``.

    ``realpath`` also answers for paths that do not exist, so a target that a
    later command in the same line creates still resolves.
    """
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded):
        expanded = os.path.join(cwd, expanded)
    return os.path.realpath(expanded)


def is_within(target: str, root: str) -> bool:
    try:
        return os.path.commonpath([root, target]) == root
    except ValueError:
        # Uncomparable roots (different drives): treat as outside (safe).
        return False
