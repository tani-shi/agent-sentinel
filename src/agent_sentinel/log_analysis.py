"""Offline audit and replay for evaluation events."""

from __future__ import annotations

from typing import Any

from agent_sentinel import evaluator
from agent_sentinel.policy_snapshot import policy_details


def replay_event(event: dict[str, Any]) -> dict[str, Any]:
    event_id = event.get("event_id", "")
    request = event.get("request")
    if not isinstance(request, dict):
        return _unreplayable(event_id, "The event does not contain a schema v3 request")
    tool = request.get("tool", "")
    if tool == "Bash":
        tool_input = {"command": request.get("command", "")}
    elif tool in {"Read", "Write", "Edit"}:
        tool_input = {"file_path": request.get("file_path", "")}
    else:
        return _unreplayable(event_id, f"Replay is not available for {tool or 'unknown tools'}")

    hook_input = {
        "hook_event_name": event.get("phase", "PreToolUse"),
        "tool_name": tool,
        "tool_input": tool_input,
        "session_id": event.get("session_id", ""),
        "cwd": event.get("cwd", "."),
    }
    host = event.get("host", "claude")
    result = (
        evaluator.evaluate_codex(hook_input)
        if host == "codex"
        else evaluator.evaluate(hook_input, judge="disabled")
    )
    if result is None:
        if host == "codex":
            owner, stage, reason = evaluator.codex_defer_target(hook_input)
            current = {
                "result": "defer",
                "owner": owner,
                "stage": stage,
                "reason": reason,
            }
        else:
            current = {
                "result": "passthrough",
                "owner": "native",
                "stage": "PASSTHROUGH",
                "reason": "Unknown tool passthrough",
            }
    else:
        decision, reason, stage = result
        current = {
            "result": decision,
            "owner": "hook",
            "stage": stage,
            "reason": reason,
        }

    recorded = _recorded_decision(event)
    comparable = not (
        host == "claude"
        and current["stage"] == "JUDGE_DISABLED"
        and recorded.get("stage", "").startswith("LLM_JUDGE")
    )
    changed = comparable and any(
        recorded.get(field) != current.get(field) for field in ("result", "owner", "stage")
    )
    current_policy = policy_details(host)
    recorded_policy = event.get("policy", {})
    return {
        "event_id": event_id,
        "replayable": True,
        "comparable": comparable,
        "changed": changed if comparable else None,
        "policy_changed": recorded_policy.get("policy_hash") != current_policy["policy_hash"],
        "recorded": recorded,
        "current": current,
    }


def audit_events(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    evaluations = {
        event.get("event_id", ""): event
        for event in events
        if event.get("event_type", "evaluation") == "evaluation"
    }
    for event in evaluations.values():
        findings.extend(_audit_evaluation(event))
    for annotation in events:
        if annotation.get("event_type") != "annotation":
            continue
        target = annotation.get("target_event_id", "")
        if target not in evaluations:
            continue
        label = annotation.get("label", "")
        if label == "missed-deny":
            findings.append(
                _finding(target, "high", "USER_REPORTED_MISSED_DENY", annotation.get("note", ""))
            )
        elif label == "false-positive":
            findings.append(
                _finding(
                    target,
                    "medium",
                    "USER_REPORTED_FALSE_POSITIVE",
                    annotation.get("note", ""),
                )
            )
        elif label == "expected-prompt":
            findings.append(
                _finding(target, "medium", "USER_EXPECTED_PROMPT", annotation.get("note", ""))
            )
    return findings


def _audit_evaluation(event: dict[str, Any]) -> list[dict[str, str]]:
    event_id = event.get("event_id", "")
    if event.get("schema_version", 0) < 3:
        return []
    findings = []
    recorded = _recorded_decision(event)
    if recorded.get("stage") == "EVALUATION_ERROR":
        findings.append(
            _finding(
                event_id,
                "high",
                "EVALUATION_FAILED_CLOSED",
                "Policy evaluation raised an exception and returned a fail-closed DENY",
            )
        )

    policy = event.get("policy", {})
    if event.get("host") == "codex" and policy.get("hook_definition_matches") is False:
        findings.append(
            _finding(
                event_id,
                "high",
                "CODEX_HOOK_DEFINITION_DRIFT",
                "Installed Codex hook definition differs from the package policy",
            )
        )
    if event.get("host") == "codex" and policy.get("execpolicy_matches") is False:
        findings.append(
            _finding(
                event_id,
                "high",
                "CODEX_EXECPOLICY_DRIFT",
                "Installed Codex execution rules differ from the package policy",
            )
        )

    analysis = event.get("analysis", {})
    for segment in analysis.get("segments", []):
        raw = segment.get("raw", "")
        if segment.get("verdict") == "deny" and recorded.get("result") != "deny":
            findings.append(
                _finding(
                    event_id,
                    "critical",
                    "DENY_BYPASS",
                    f"DENY segment was not blocked: {raw}",
                )
            )
        if (
            segment.get("verdict") == "ask"
            and segment.get("has_execpolicy_rule")
            and not segment.get("execpolicy_covered")
            and recorded.get("result") != "deny"
        ):
            findings.append(
                _finding(
                    event_id,
                    "high",
                    "ASK_NOT_COVERED_BY_EXECPOLICY",
                    f"ASK segment was delegated without prompt coverage: {raw}",
                )
            )

    replay = replay_event(event)
    if replay.get("changed"):
        findings.append(
            _finding(
                event_id,
                "medium",
                "POLICY_DECISION_CHANGED",
                "Current policy produces a different result, owner, or stage",
            )
        )
    return findings


def _recorded_decision(event: dict[str, Any]) -> dict[str, str]:
    decision = event.get("decision", {})
    if isinstance(decision, dict):
        return {
            "result": str(decision.get("result", "")),
            "owner": str(decision.get("owner", "")),
            "stage": str(decision.get("stage", "")),
            "reason": str(decision.get("reason", "")),
        }
    return {
        "result": str(decision),
        "owner": str(event.get("owner", "")),
        "stage": str(event.get("stage", "")),
        "reason": str(event.get("reason", "")),
    }


def _unreplayable(event_id: str, reason: str) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "replayable": False,
        "comparable": False,
        "changed": None,
        "policy_changed": None,
        "reason": reason,
    }


def _finding(event_id: str, severity: str, code: str, message: str) -> dict[str, str]:
    return {
        "event_id": event_id,
        "severity": severity,
        "code": code,
        "message": message,
    }
