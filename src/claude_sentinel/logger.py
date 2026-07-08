"""Evaluation log writer and reader."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _default_log_dir() -> Path:
    """Return platform-appropriate default log directory."""
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            return Path(local) / "claude-sentinel" / "logs"
    return Path.home() / ".local" / "share" / "claude-sentinel" / "logs"


DEFAULT_LOG_DIR = _default_log_dir()
LOG_FILENAME = "eval.jsonl"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_FILES = 5


def get_log_dir() -> Path:
    """Return the log directory, respecting CLAUDE_SENTINEL_LOG_DIR env var."""
    env = os.environ.get("CLAUDE_SENTINEL_LOG_DIR")
    if env:
        return Path(env)
    return DEFAULT_LOG_DIR


def log_evaluation(
    hook_input: dict[str, Any],
    decision: str,
    reason: str,
    stage: str,
    elapsed_ms: float,
) -> None:
    """Append one evaluation record to the log file.

    Silently ignores all errors so logging never affects hook decisions.
    """
    try:
        log_dir = get_log_dir()
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / LOG_FILENAME

        tool_name = hook_input.get("tool_name", "")
        tool_input = hook_input.get("tool_input", {})
        if tool_name == "Bash":
            input_value = tool_input.get("command", "")
        elif tool_name in ("Read", "Write", "Edit"):
            input_value = tool_input.get("file_path", "")
        else:
            input_value = json.dumps(tool_input, ensure_ascii=False)

        record = {
            "ts": datetime.now(UTC).isoformat(),
            "session_id": hook_input.get("session_id", ""),
            "tool_name": tool_name,
            "input": input_value,
            "cwd": hook_input.get("cwd", ""),
            "decision": decision,
            "stage": stage,
            "reason": reason,
            "elapsed_ms": round(elapsed_ms, 1),
        }

        _rotate_if_needed(log_path)

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _rotate_if_needed(log_path: Path) -> None:
    """Rotate log files if the current file exceeds MAX_FILE_SIZE."""
    if not log_path.exists():
        return
    if log_path.stat().st_size <= MAX_FILE_SIZE:
        return

    # Shift existing rotated files: .4 -> delete, .3 -> .4, .2 -> .3, .1 -> .2
    for i in range(MAX_FILES, 1, -1):
        src = log_path.parent / f"{LOG_FILENAME}.{i - 1}"
        dst = log_path.parent / f"{LOG_FILENAME}.{i}"
        if src.exists():
            if i == MAX_FILES:
                dst.unlink(missing_ok=True)
            src.rename(dst)

    # Current -> .1
    log_path.rename(log_path.parent / f"{LOG_FILENAME}.1")


def iter_logs(
    log_dir: Path | None = None,
    *,
    since: float | None = None,
    decision: str | None = None,
    stage: str | None = None,
    limit: int = 0,
    newest_first: bool = True,
) -> Iterator[dict[str, Any]]:
    """Iterate over log records with optional filters.

    Args:
        log_dir: Directory containing log files. Defaults to get_log_dir().
        since: Unix timestamp; only yield records newer than this.
        decision: Filter by decision (e.g. "allow", "deny").
        stage: Filter by stage (e.g. "RULE_DENY", "RULE_ALLOW", "LLM_JUDGE").
        limit: Maximum number of records to yield. 0 means unlimited.
        newest_first: If True, yield newest records first.
    """
    if log_dir is None:
        log_dir = get_log_dir()

    # Collect all log files in order: eval.jsonl (newest), .1, .2, ...
    files: list[Path] = []
    main_log = log_dir / LOG_FILENAME
    if main_log.exists():
        files.append(main_log)
    for i in range(1, MAX_FILES + 1):
        rotated = log_dir / f"{LOG_FILENAME}.{i}"
        if rotated.exists():
            files.append(rotated)

    if not files:
        return

    # Read all matching records
    records: list[dict[str, Any]] = []
    for fp in files:
        try:
            with open(fp, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not _matches(rec, since=since, decision=decision, stage=stage):
                        continue
                    records.append(rec)
        except OSError:
            continue

    # Sort by timestamp
    records.sort(key=lambda r: r.get("ts", ""), reverse=newest_first)

    count = 0
    for rec in records:
        yield rec
        count += 1
        if limit and count >= limit:
            return


def _matches(
    rec: dict[str, Any],
    *,
    since: float | None,
    decision: str | None,
    stage: str | None,
) -> bool:
    if decision and rec.get("decision") != decision:
        return False
    if stage and rec.get("stage") != stage:
        return False
    if since is not None:
        ts_str = rec.get("ts", "")
        try:
            rec_ts = datetime.fromisoformat(ts_str).timestamp()
        except (ValueError, TypeError):
            return False
        if rec_ts < since:
            return False
    return True
