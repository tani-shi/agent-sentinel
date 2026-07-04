"""LLM-based command evaluation using Claude Code SDK."""

from __future__ import annotations

import asyncio
import time
from importlib import resources

_MODEL = "claude-haiku-4-5-20251001"
_SDK_TIMEOUT = 30.0
_MAX_RETRIES = 2
_RETRY_DELAY_SECONDS = 1.0


def _load_prompt_template() -> str:
    """Load the LLM prompt template."""
    rules_pkg = resources.files("claude_sentinel.rules")
    return (rules_pkg / "llm_prompt.txt").read_text(encoding="utf-8")


async def _evaluate_sdk(prompt: str) -> tuple[str, str]:
    """Evaluate using Claude Code SDK (async)."""
    from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

    options = ClaudeAgentOptions(
        model=_MODEL,
        max_turns=1,
        permission_mode="bypassPermissions",
        allowed_tools=[],
        env={"CLAUDECODE": "", "CLAUDE_CODE_ENTRYPOINT": ""},
    )

    result_text = ""
    async with asyncio.timeout(_SDK_TIMEOUT):
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, ResultMessage):
                result_text = message.result or ""

    return _parse_response(result_text.strip())


def evaluate(command: str, cwd: str) -> tuple[str, str]:
    """Evaluate a command using the LLM judge.

    Returns:
        (decision, reason) where decision is "allow", "deny", or "ask"
    """
    prompt = _load_prompt_template().format(command=command, cwd=cwd)
    last_error = ""
    for attempt in range(_MAX_RETRIES):
        try:
            return asyncio.run(_evaluate_sdk(prompt))
        except TimeoutError:
            last_error = "LLM judge timed out"
            if attempt < _MAX_RETRIES - 1:
                time.sleep(_RETRY_DELAY_SECONDS * (attempt + 1))
        except Exception as e:
            return "ask", f"LLM judge error: {e}"
    return "ask", last_error


def _parse_response(output: str) -> tuple[str, str]:
    """Parse the LLM response into (decision, reason)."""
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
