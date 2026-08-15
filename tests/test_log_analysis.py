"""Tests for offline log audit and replay."""

from agent_sentinel import log_analysis, logger


def _bash_event(
    command: str,
    *,
    result: str,
    stage: str,
    owner: str,
) -> dict:
    event = logger.build_evaluation_event(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "session_id": "task-1",
            "cwd": "/tmp",
        },
        result,
        "test decision",
        stage,
        1.0,
        host="codex",
        owner=owner,
    )
    event["policy"]["hook_definition_matches"] = True
    event["policy"]["execpolicy_matches"] = True
    return event


def test_replay_preserves_execpolicy_defer():
    event = _bash_event(
        "ssh production",
        result="defer",
        stage="CODEX_RULE_PROMPT",
        owner="execpolicy",
    )

    replay = log_analysis.replay_event(event)

    assert replay["replayable"] is True
    assert replay["changed"] is False
    assert replay["current"]["result"] == "defer"
    assert replay["current"]["owner"] == "execpolicy"


def test_replay_detects_changed_policy_decision():
    event = _bash_event(
        "command git commit -m message",
        result="defer",
        stage="CODEX_NATIVE",
        owner="native",
    )

    replay = log_analysis.replay_event(event)

    assert replay["changed"] is True
    assert replay["current"]["result"] == "deny"
    assert replay["current"]["stage"] == "CODEX_RULE_DENY"


def test_audit_detects_uncovered_ask():
    event = _bash_event(
        "command git commit -m message",
        result="defer",
        stage="CODEX_NATIVE",
        owner="native",
    )

    findings = log_analysis.audit_events([event])

    assert {finding["code"] for finding in findings} == {
        "ASK_NOT_COVERED_BY_EXECPOLICY",
        "POLICY_DECISION_CHANGED",
    }


def test_audit_detects_deny_bypass():
    event = _bash_event(
        "/usr/bin/pkill worker",
        result="defer",
        stage="CODEX_NATIVE",
        owner="native",
    )

    findings = log_analysis.audit_events([event])

    assert "DENY_BYPASS" in {finding["code"] for finding in findings}


def test_audit_detects_installed_codex_policy_drift():
    event = _bash_event("ls", result="defer", stage="CODEX_NATIVE", owner="native")
    event["policy"]["hook_definition_matches"] = False
    event["policy"]["execpolicy_matches"] = False

    findings = log_analysis.audit_events([event])

    codes = {finding["code"] for finding in findings}
    assert "CODEX_HOOK_DEFINITION_DRIFT" in codes
    assert "CODEX_EXECPOLICY_DRIFT" in codes


def test_audit_includes_user_feedback():
    event = _bash_event("ls", result="defer", stage="CODEX_NATIVE", owner="native")
    annotation = {
        "schema_version": 3,
        "event_type": "annotation",
        "event_id": "annotation-1",
        "target_event_id": event["event_id"],
        "label": "false-positive",
        "note": "Expected native execution",
    }

    findings = log_analysis.audit_events([event, annotation])

    assert any(finding["code"] == "USER_REPORTED_FALSE_POSITIVE" for finding in findings)


def test_schema_two_event_is_not_replayable():
    replay = log_analysis.replay_event(
        {"schema_version": 2, "event_id": "old", "decision": "deny"}
    )

    assert replay["replayable"] is False
    assert "schema v3" in replay["reason"]
