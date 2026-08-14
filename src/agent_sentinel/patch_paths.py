"""Extract file paths from an apply_patch command."""

from __future__ import annotations

from pathlib import Path

_PATH_HEADERS = (
    "*** Add File: ",
    "*** Update File: ",
    "*** Delete File: ",
    "*** Move to: ",
)


def extract_paths(patch: str, cwd: str) -> list[str]:
    """Return normalized paths named by apply_patch operation headers."""
    base = Path(cwd)
    paths: list[str] = []
    for line in patch.splitlines():
        path_text = next(
            (line.removeprefix(prefix) for prefix in _PATH_HEADERS if line.startswith(prefix)),
            None,
        )
        if path_text is None:
            continue
        path = Path(path_text.strip())
        if not path.is_absolute():
            path = base / path
        normalized = str(path.resolve(strict=False))
        if normalized not in paths:
            paths.append(normalized)
    return paths
