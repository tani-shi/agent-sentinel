"""LLM-based command evaluation using Claude Code SDK."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from importlib import resources
from typing import Any

_MODEL = "claude-haiku-4-5-20251001"
# Empties suppress the parent Claude Code session's env so the judge runs as a
# standalone query rather than a nested tool call.
_JUDGE_ENV = {"CLAUDECODE": "", "CLAUDE_CODE_ENTRYPOINT": ""}
_SDK_TIMEOUT = 30.0
_PLAIN_MAX_TURNS = 2
_MAX_RETRIES = 2
_RETRY_DELAY_SECONDS = 1.0

# Read mode's budgets exceed the plain mode's because a Read + final-answer cycle
# spends more than one turn, and reading a file over the network is slower than a
# plain text reply.
_READ_MAX_TURNS = 6
_READ_SDK_TIMEOUT = 60.0


def _load_prompt_template(filename: str) -> str:
    """Load an LLM prompt template from the rules package."""
    rules_pkg = resources.files("agent_sentinel.rules")
    return (rules_pkg / filename).read_text(encoding="utf-8")


async def _evaluate_sdk(prompt: str, options: Any, timeout: float) -> tuple[str, str]:
    """Run one judge query through the Claude Agent SDK and parse its verdict."""
    from claude_agent_sdk import ResultMessage, query

    async with asyncio.timeout(timeout):
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, ResultMessage):
                # Return on the terminal ResultMessage rather than iterating
                # further: a lingering stream would otherwise let the timeout
                # discard a verdict already in hand.
                if message.subtype == "success":
                    return _parse_response((message.result or "").strip())
                # Non-success subtypes (error_max_turns, …) have no `result`.
                return "ask", f"LLM judge incomplete: {message.subtype}"

    return _parse_response("")


def _plain_options() -> Any:
    from claude_agent_sdk import ClaudeAgentOptions

    return ClaudeAgentOptions(
        model=_MODEL,
        tools=[],
        max_turns=_PLAIN_MAX_TURNS,
        permission_mode="bypassPermissions",
        allowed_tools=[],
        env=_JUDGE_ENV,
    )


def _read_options(cwd: str, read_dirs: Sequence[str]) -> Any:
    from pathlib import Path

    from claude_agent_sdk import ClaudeAgentOptions

    add_dirs: list[str | Path] = [*read_dirs]
    return ClaudeAgentOptions(
        model=_MODEL,
        tools=["Read"],
        max_turns=_READ_MAX_TURNS,
        permission_mode="bypassPermissions",
        allowed_tools=["Read"],
        cwd=cwd,
        add_dirs=add_dirs,
        env=_JUDGE_ENV,
    )


def evaluate(command: str, cwd: str, read_dirs: Sequence[str] | None = None) -> tuple[str, str]:
    """Evaluate a command using the LLM judge.

    Returns (decision, reason) where decision is "allow", "deny", or "ask".
    Clearly dangerous commands are denied; commands needing human judgment are
    asked. A timeout or error falls back to "ask" so the human decides.

    When ``read_dirs`` is given, the judge runs in read mode: it is granted the
    built-in Read tool scoped to ``cwd`` plus ``read_dirs`` so it can inspect
    out-of-project script files the command executes before deciding.
    """
    try:
        if read_dirs:
            prompt = _load_prompt_template("llm_prompt_read.txt").format(command=command, cwd=cwd)
            options = _read_options(cwd, read_dirs)
            timeout = _READ_SDK_TIMEOUT
        else:
            prompt = _load_prompt_template("llm_prompt.txt").format(command=command, cwd=cwd)
            options = _plain_options()
            timeout = _SDK_TIMEOUT
    except ImportError as error:
        return "ask", f"LLM judge unavailable: {error}"

    last_error = ""
    for attempt in range(_MAX_RETRIES):
        try:
            return asyncio.run(_evaluate_sdk(prompt, options, timeout))
        except TimeoutError:
            last_error = "LLM judge timed out"
            if attempt < _MAX_RETRIES - 1:
                time.sleep(_RETRY_DELAY_SECONDS * (attempt + 1))
        except Exception as e:
            return "ask", f"LLM judge error: {e}"
    return "ask", last_error


def _parse_response(output: str) -> tuple[str, str]:
    """Parse the LLM response into (decision, reason).

    An empty or unexpected response falls back to "ask" so the human decides.
    """
    if not output:
        return "ask", "Empty LLM response"

    lines = output.strip().splitlines()
    first_line = lines[0].strip().upper()
    reason = lines[1].strip() if len(lines) > 1 else "No reason provided"

    if first_line == "ALLOW":
        return "allow", reason
    elif first_line == "DENY":
        return "deny", reason
    elif first_line == "ASK":
        return "ask", reason
    else:
        return "ask", f"Unexpected LLM response: {lines[0]}"
