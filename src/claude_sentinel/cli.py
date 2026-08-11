"""CLI entry point for claude-sentinel."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import IO

from claude_sentinel import (
    evaluator,
    hook_io,
    installer,
    logger,
    rule_engine,
)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="claude-sentinel",
        description="Claude Code hook for evaluating tool permission requests",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Output decision reason to stderr",
    )
    parser.add_argument(
        "--test",
        metavar="COMMAND",
        help="Test a command with synthetic hook input",
    )

    subparsers = parser.add_subparsers(dest="subcommand")
    install_parser = subparsers.add_parser(
        "install", help="Install hooks into Claude Code settings"
    )
    install_parser.add_argument(
        "--path",
        metavar="FILE",
        help="Path to settings.json (default: ~/.claude/settings.json)",
    )
    uninstall_parser = subparsers.add_parser(
        "uninstall", help="Remove hooks from Claude Code settings"
    )
    uninstall_parser.add_argument(
        "--path",
        metavar="FILE",
        help="Path to settings.json (default: ~/.claude/settings.json)",
    )

    # rules subcommand
    rules_parser = subparsers.add_parser("rules", help="Display all rules")
    rules_parser.add_argument(
        "--kind",
        choices=["deny", "allow", "ask"],
        help="Filter by rule kind",
    )
    rules_parser.add_argument(
        "--type",
        choices=["Bash", "sensitive-path"],
        help="Filter by rule type",
    )
    rules_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="JSON Lines output",
    )

    # log subcommand
    log_parser = subparsers.add_parser("log", help="View evaluation logs")
    log_parser.add_argument(
        "-n", type=int, default=20, help="Number of records to show (default: 20)"
    )
    log_parser.add_argument(
        "--decision", choices=["allow", "deny", "ask"], help="Filter by decision"
    )
    log_parser.add_argument(
        "--stage",
        choices=["RULE_DENY", "RULE_ALLOW", "RULE_ASK", "LLM_JUDGE", "LLM_JUDGE_READ"],
        help="Filter by stage",
    )
    log_parser.add_argument("--since", help="Show records since (e.g. 1h, 30m, 2d)")
    log_parser.add_argument(
        "--json", action="store_true", dest="json_output", help="Raw JSON Lines output"
    )
    log_parser.add_argument(
        "--tail", action="store_true", help="Show oldest first (chronological order)"
    )
    log_parser.add_argument(
        "-f", "--follow", action="store_true", help="Follow log in real-time (tail -f)"
    )
    log_parser.add_argument(
        "--path", action="store_true", help="Print log directory path and exit"
    )

    args = parser.parse_args(argv)

    if args.subcommand == "install":
        settings_path = Path(args.path) if args.path else None
        msg = installer.install(settings_path)
        print(msg)
        return

    if args.subcommand == "uninstall":
        settings_path = Path(args.path) if args.path else None
        msg = installer.uninstall(settings_path)
        print(msg)
        return

    if args.subcommand == "rules":
        _run_rules(args)
        return

    if args.subcommand == "log":
        _run_log(args)
        return

    if args.test:
        _run_test(args.test, explain=args.explain)
        return

    # Default: hook mode — read from stdin, evaluate, write to stdout
    _run_hook(explain=args.explain)


def _run_rules(args: argparse.Namespace) -> None:
    """Handle the rules subcommand."""
    kinds = [args.kind] if args.kind else ["deny", "allow", "ask"]
    type_filter = args.type

    for kind in kinds:
        ruleset = rule_engine.load_rules(kind=kind)

        if type_filter is None or type_filter == "Bash":
            for rule in ruleset.command_rules:
                if args.json_output:
                    print(
                        json.dumps(
                            {
                                "kind": kind,
                                "type": "Bash",
                                "name": rule.name,
                                "pattern": rule.pattern.pattern,
                                "deny_if": rule.deny_if,
                            }
                        )
                    )
                else:
                    _print_rule_section(kind, "Bash", ruleset.command_rules)
                    break

        if type_filter is None or type_filter == "sensitive-path":
            for rule in ruleset.sensitive_path_rules:
                if args.json_output:
                    print(
                        json.dumps(
                            {
                                "kind": kind,
                                "type": "sensitive-path",
                                "name": rule.name,
                                "pattern": rule.pattern.pattern,
                                "path_glob": list(rule.path_globs),
                            }
                        )
                    )
                else:
                    _print_rule_section(kind, "sensitive-path", ruleset.sensitive_path_rules)
                    break

    # Auto-allow tools
    if not args.kind and not type_filter:
        if args.json_output:
            for tool in sorted(evaluator.AUTO_ALLOW_TOOLS):
                print(json.dumps({"kind": "auto-allow", "type": "tool", "name": tool}))
        else:
            print("\nAuto-allow tools:")
            for tool in sorted(evaluator.AUTO_ALLOW_TOOLS):
                print(f"  {tool}")


_DENY_IF_LABELS = {"git-alias-discard": "escalates to deny where `git discard` exists"}


def _print_rule_section(kind: str, rule_type: str, rules: list) -> None:
    """Print a section of rules in human-readable format."""
    if not rules:
        return
    label = kind.capitalize()
    print(f"\n{label} rules ({rule_type}):")
    max_name = max(len(r.name) for r in rules)
    for rule in rules:
        print(f"  {rule.name:<{max_name}}  {rule.pattern.pattern}")
        if rule.deny_if:
            print(f"  {'':<{max_name}}  [{_DENY_IF_LABELS.get(rule.deny_if, rule.deny_if)}]")


def _run_test(command: str, *, explain: bool = False) -> None:
    """Test a command with synthetic hook input."""
    import os

    hook_input = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "session_id": "test",
        "cwd": os.getcwd(),
    }

    t0 = time.monotonic()
    result = evaluator.evaluate(hook_input)
    elapsed_ms = (time.monotonic() - t0) * 1000

    if result is None:
        print("PASS (unknown tool, passthrough)")
        return

    decision, reason, stage = result
    logger.log_evaluation(hook_input, decision, reason, stage, elapsed_ms)
    print(f"{decision.upper()} [{stage}]: {reason}")

    if explain:
        print(f"  Command: {command}", file=sys.stderr)


def _run_hook(*, explain: bool = False) -> None:
    """Run in hook mode: read stdin JSON, evaluate, write stdout JSON."""
    try:
        hook_input = hook_io.read_input()
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        sys.exit(1)

    t0 = time.monotonic()
    result = evaluator.evaluate(hook_input)
    elapsed_ms = (time.monotonic() - t0) * 1000

    if result is None:
        # Unknown tool: passthrough (exit 0, no output)
        return

    decision, reason, stage = result
    logger.log_evaluation(hook_input, decision, reason, stage, elapsed_ms)

    if explain:
        tool_name = hook_input.get("tool_name", "")
        print(f"[claude-sentinel] {tool_name}: {decision} [{stage}] {reason}", file=sys.stderr)

    hook_io.write_output(decision, reason)


def _run_log(args: argparse.Namespace) -> None:
    """Handle the log subcommand."""
    if args.path:
        print(logger.get_log_dir())
        return

    if args.follow:
        _follow_log(args)
        return

    since_ts = _parse_since(args.since) if args.since else None

    records = logger.iter_logs(
        since=since_ts,
        decision=args.decision,
        stage=args.stage,
        limit=args.n,
        newest_first=not args.tail,
    )

    for rec in records:
        if args.json_output:
            print(json.dumps(rec, ensure_ascii=False))
        else:
            _print_record(rec)


def _follow_log(args: argparse.Namespace) -> None:
    """Follow the log file in real-time."""
    log_path = logger.get_log_dir() / logger.LOG_FILENAME
    f: IO[str] | None = None
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        # Start from end of file if it exists
        try:
            f = open(log_path, encoding="utf-8")
            f.seek(0, 2)  # Seek to end
        except FileNotFoundError:
            # Wait for file to be created
            print(f"Waiting for {log_path} ...", file=sys.stderr)
            while not log_path.exists():
                time.sleep(0.5)
            f = open(log_path, encoding="utf-8")

        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    if args.json_output:
                        print(line, flush=True)
                    else:
                        try:
                            rec = json.loads(line)
                            _print_record(rec)
                            sys.stdout.flush()
                        except json.JSONDecodeError:
                            pass
            else:
                time.sleep(0.3)
    except KeyboardInterrupt:
        pass
    finally:
        if f is not None:
            f.close()


def _print_record(rec: dict) -> None:
    """Print a single record in human-readable format."""
    ts = rec.get("ts", "")
    # Trim to seconds for display
    try:
        from datetime import datetime

        dt = datetime.fromisoformat(ts)
        ts_display = dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        ts_display = ts

    decision = rec.get("decision", "").upper()
    stage = rec.get("stage", "")
    tool_name = rec.get("tool_name", "")
    input_val = rec.get("input", "")
    reason = rec.get("reason", "")
    elapsed = rec.get("elapsed_ms", 0)

    print(f"{ts_display} {decision} [{stage}] {tool_name}: {input_val}")
    print(f"  {reason} ({elapsed}ms)")


def _parse_since(value: str) -> float:
    """Parse a relative time string like '1h', '30m', '2d' to a Unix timestamp."""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if not value:
        raise argparse.ArgumentTypeError("empty --since value")

    unit = value[-1].lower()
    if unit not in units:
        raise argparse.ArgumentTypeError(f"Invalid time unit '{unit}'. Use s, m, h, or d.")
    try:
        amount = float(value[:-1])
    except ValueError as err:
        raise argparse.ArgumentTypeError(f"Invalid number in '{value}'") from err

    return time.time() - (amount * units[unit])


if __name__ == "__main__":
    main()
