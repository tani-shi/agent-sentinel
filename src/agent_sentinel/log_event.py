"""Schema v3 evaluation event construction."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from agent_sentinel import codex_policy, rule_engine
from agent_sentinel.command_normalizer import normalize_for_matching
from agent_sentinel.patch_paths import extract_paths
from agent_sentinel.policy_snapshot import policy_details

LOG_SCHEMA_VERSION = 3


def build_evaluation_event(
    hook_input: dict[str, Any],
    decision: str,
    reason: str,
    stage: str,
    elapsed_ms: float,
    *,
    host: str,
    owner: str,
) -> dict[str, Any]:
    request = _request_details(hook_input)
    analysis = _safe_analysis_details(hook_input, request)
    reason_code = _reason_code(decision, stage, owner, analysis)
    return {
        "schema_version": LOG_SCHEMA_VERSION,
        "event_type": "evaluation",
        "event_id": uuid.uuid4().hex,
        "ts": datetime.now(UTC).isoformat(),
        "host": host,
        "phase": hook_input.get("hook_event_name", "PreToolUse"),
        "session_id": hook_input.get("session_id", ""),
        "cwd": hook_input.get("cwd", ""),
        "request": request,
        "analysis": analysis,
        "decision": {
            "result": decision,
            "owner": owner,
            "stage": stage,
            "reason_code": reason_code,
            "reason": reason,
            "expected_action": _expected_action(decision, owner),
            "observed_outcome": "unknown",
        },
        "policy": policy_details(host),
        "elapsed_ms": round(elapsed_ms, 1),
    }


def _safe_analysis_details(hook_input: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    try:
        return _analysis_details(hook_input, request)
    except Exception as error:
        return {"status": "unavailable", "error_type": type(error).__name__}


def _request_details(hook_input: dict[str, Any]) -> dict[str, Any]:
    tool = str(hook_input.get("tool_name", ""))
    tool_input = hook_input.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = {}
    request: dict[str, Any] = {"tool": tool}
    hash_value: Any = tool
    if tool == "Bash":
        hash_value = request["command"] = str(tool_input.get("command", ""))
    elif tool in {"Read", "Write", "Edit"}:
        hash_value = request["file_path"] = str(tool_input.get("file_path", ""))
    elif tool == "apply_patch":
        hash_value = request["paths"] = extract_paths(
            str(tool_input.get("command", "")), str(hook_input.get("cwd", "."))
        )
    request["sha256"] = _digest(hash_value)
    return request


def _analysis_details(hook_input: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    tool = request["tool"]
    cwd = str(hook_input.get("cwd", "."))
    if tool == "Bash":
        command = request.get("command", "")
        inspection = rule_engine.inspect_bash_command(command, cwd)
        segments = []
        for segment in inspection.segments:
            verdict = segment.verdict
            matched_rules = []
            if verdict.name:
                matched_rules.append({"id": verdict.name, "effect": verdict.decision})
            has_execpolicy_rule = bool(verdict.name and codex_policy.has_prompt_rule(verdict.name))
            segments.append(
                {
                    "raw": segment.raw,
                    "normalized": segment.normalized,
                    "normalization": list(segment.normalization),
                    "verdict": verdict.decision,
                    "matched_rules": matched_rules,
                    "has_execpolicy_rule": has_execpolicy_rule,
                    "execpolicy_covered": (
                        codex_policy.prompt_covers(verdict.name, segment.raw)
                        if has_execpolicy_rule
                        else False
                    ),
                }
            )
        return {
            "parsed": inspection.parsed,
            "normalized_command": normalize_for_matching(command),
            "segments": segments,
        }

    if tool in {"Read", "Write", "Edit"}:
        path = request.get("file_path", "")
        match = rule_engine.match_sensitive_path(path)
        return {"matched_rules": [match.name] if match else []}

    if tool == "apply_patch":
        paths = request.get("paths", [])
        return {
            "paths": [
                {
                    "path": path,
                    "matched_rule": (
                        match.name if (match := rule_engine.match_sensitive_path(path)) else None
                    ),
                }
                for path in paths
            ]
        }
    return {}


def _reason_code(decision: str, stage: str, owner: str, analysis: dict[str, Any]) -> str:
    if stage == "EVALUATION_ERROR":
        return "EVALUATION_FAILED_CLOSED"
    if stage == "INPUT_DENY":
        return "INVALID_INPUT_BLOCKED"
    if stage == "CODEX_RULE_PROMPT":
        return "ASK_COVERED_BY_EXECPOLICY"
    if stage == "CODEX_NATIVE":
        return "DELEGATED_TO_NATIVE"
    if stage == "CODEX_RULE_DENY":
        uncovered = any(
            segment.get("has_execpolicy_rule") and not segment.get("execpolicy_covered")
            for segment in analysis.get("segments", [])
        )
        return "ASK_NOT_COVERED_BY_EXECPOLICY" if uncovered else "CODEX_RULE_BLOCKED"
    if stage == "RULE_DENY":
        return "STATIC_DENY_MATCHED"
    if stage == "RULE_ASK":
        return "STATIC_ASK_MATCHED"
    if stage == "RULE_ALLOW":
        return "STATIC_ALLOW_MATCHED"
    if owner == "execpolicy":
        return "DELEGATED_TO_EXECPOLICY"
    return stage or decision.upper()


def _expected_action(decision: str, owner: str) -> str:
    if decision == "deny":
        return "block"
    if decision == "ask" or owner == "execpolicy":
        return "prompt"
    if decision == "allow":
        return "allow"
    return "native"


def _digest(value: Any) -> str:
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
