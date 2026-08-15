"""Evaluation event writer and reader."""

from __future__ import annotations

import json
import os
import sys
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent_sentinel.log_event import LOG_SCHEMA_VERSION, build_evaluation_event


def _default_log_dir() -> Path:
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            return Path(local) / "agent-sentinel" / "logs"
    return Path.home() / ".local" / "share" / "agent-sentinel" / "logs"


def _legacy_log_dir() -> Path:
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            return Path(local) / "claude-sentinel" / "logs"
    return Path.home() / ".local" / "share" / "claude-sentinel" / "logs"


DEFAULT_LOG_DIR = _default_log_dir()
LEGACY_LOG_DIR = _legacy_log_dir()
LOG_FILENAME = "eval.jsonl"
MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_FILES = 5


def get_log_dir() -> Path:
    env = os.environ.get("AGENT_SENTINEL_LOG_DIR") or os.environ.get("CLAUDE_SENTINEL_LOG_DIR")
    if env:
        return Path(env)
    return DEFAULT_LOG_DIR


def log_evaluation(
    hook_input: dict[str, Any],
    decision: str,
    reason: str,
    stage: str,
    elapsed_ms: float,
    *,
    host: str = "claude",
    owner: str = "hook",
) -> str | None:
    """Append one replayable evaluation event without affecting hook decisions."""
    try:
        event = build_evaluation_event(
            hook_input,
            decision,
            reason,
            stage,
            elapsed_ms,
            host=host,
            owner=owner,
        )
        _append_event(event)
        return event["event_id"]
    except Exception:
        return None


def append_annotation(target_event_id: str, label: str, note: str = "") -> str:
    if find_event(target_event_id) is None:
        raise ValueError(f"Evaluation event not found: {target_event_id}")
    event_id = uuid.uuid4().hex
    _append_event(
        {
            "schema_version": LOG_SCHEMA_VERSION,
            "event_type": "annotation",
            "event_id": event_id,
            "ts": datetime.now(UTC).isoformat(),
            "target_event_id": target_event_id,
            "label": label,
            "note": note,
        }
    )
    return event_id


def prepare_log_dir() -> Path:
    log_dir = get_log_dir()
    log_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    if hasattr(os, "chmod"):
        os.chmod(log_dir, 0o700)
    for index in range(MAX_FILES + 1):
        suffix = "" if index == 0 else f".{index}"
        path = log_dir / f"{LOG_FILENAME}{suffix}"
        if path.is_file() and not path.is_symlink():
            os.chmod(path, 0o600)
    return log_dir


def _append_event(event: dict[str, Any]) -> None:
    log_path = prepare_log_dir() / LOG_FILENAME
    _rotate_if_needed(log_path)
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(log_path, flags, 0o600)
    if hasattr(os, "fchmod"):
        os.fchmod(fd, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=False) + "\n")


def _rotate_if_needed(log_path: Path) -> None:
    if not log_path.exists() or log_path.stat().st_size <= MAX_FILE_SIZE:
        return
    for index in range(MAX_FILES, 1, -1):
        source = log_path.parent / f"{LOG_FILENAME}.{index - 1}"
        destination = log_path.parent / f"{LOG_FILENAME}.{index}"
        if source.exists():
            if index == MAX_FILES:
                destination.unlink(missing_ok=True)
            source.rename(destination)
    log_path.rename(log_path.parent / f"{LOG_FILENAME}.1")


def iter_events(
    log_dir: Path | None = None,
    *,
    newest_first: bool = True,
) -> Iterator[dict[str, Any]]:
    if log_dir is None:
        log_dir = get_log_dir()
        if log_dir == DEFAULT_LOG_DIR and not log_dir.exists() and LEGACY_LOG_DIR.exists():
            log_dir = LEGACY_LOG_DIR
    files = []
    for index in range(MAX_FILES + 1):
        suffix = "" if index == 0 else f".{index}"
        path = log_dir / f"{LOG_FILENAME}{suffix}"
        if path.exists():
            files.append(path)
    records = []
    for path in files:
        try:
            with path.open(encoding="utf-8") as stream:
                for line in stream:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
    records.sort(key=lambda record: record.get("ts", ""), reverse=newest_first)
    yield from records


def iter_logs(
    log_dir: Path | None = None,
    *,
    since: float | None = None,
    decision: str | None = None,
    stage: str | None = None,
    limit: int = 0,
    newest_first: bool = True,
) -> Iterator[dict[str, Any]]:
    count = 0
    for record in iter_events(log_dir, newest_first=newest_first):
        if record.get("event_type", "evaluation") != "evaluation":
            continue
        if not _matches(record, since=since, decision=decision, stage=stage):
            continue
        yield record
        count += 1
        if limit and count >= limit:
            return


def find_event(event_id: str, log_dir: Path | None = None) -> dict[str, Any] | None:
    for event in iter_logs(log_dir):
        if event.get("event_id") == event_id:
            return event
    return None


def decision_value(record: dict[str, Any]) -> str:
    decision = record.get("decision", "")
    if isinstance(decision, dict):
        return str(decision.get("result", ""))
    return str(decision)


def stage_value(record: dict[str, Any]) -> str:
    decision = record.get("decision", {})
    if isinstance(decision, dict):
        return str(decision.get("stage", ""))
    return str(record.get("stage", ""))


def _matches(
    record: dict[str, Any],
    *,
    since: float | None,
    decision: str | None,
    stage: str | None,
) -> bool:
    if decision and decision_value(record) != decision:
        return False
    if stage and stage_value(record) != stage:
        return False
    if since is not None:
        try:
            record_ts = datetime.fromisoformat(record.get("ts", "")).timestamp()
        except (ValueError, TypeError):
            return False
        if record_ts < since:
            return False
    return True
