---
description: Interactively propose ALLOW/DEFER rule additions for agent-sentinel from recent unmatched log entries
allowed-tools: Bash(agent-sentinel log:*), Bash(agent-sentinel rules:*), Bash(make check:*), Bash(git diff:*), Read, Edit
---

You are helping the user maintain `allow.toml` and `defer.toml` for
agent-sentinel — the coding-agent safety hook that evaluates shell
commands. An ALLOW skips the host reviewer (Claude Code auto mode
classifier, Codex auto-review) and saves its tokens; everything that
matches no rule defers to that reviewer. Find commands that frequently
match no rule, propose ALLOW rules for the ones that need no review,
refine the proposals **interactively** with the user, and then edit the
rule files (and tests) directly.

## Workflow

1. Fetch recent log records that matched no rule:
   ```
   agent-sentinel log --json --stage NO_RULE --since 30d -n 200
   ```
   Each record carries `request.command`, `cwd`, `analysis.segments`
   (with the segments that matched nothing), and `decision`. The hook
   never learns what the host reviewer decided, so classify by the
   command's intent and how often it recurs.

2. Fetch the existing rule sets:
   ```
   agent-sentinel rules --kind allow --json
   agent-sentinel rules --kind defer --json
   agent-sentinel rules --kind deny --json
   ```

3. Group log records by *intent*, not by surface form. Examples of
   commands that should collapse to the same intent:
   - `gh pr view 12 --json body 2>&1 | head -5` and `gh pr view 12`
   - `cd src && kubectl get pods` and `kubectl get pods` — focus on the
     unmatched segment, not the cd
   - `cat foo | grep bar` and `grep bar foo`
   Examples of related commands worth one shared rule (a family):
   - `kubectl get`, `kubectl describe`, `kubectl logs` — a single
     read-verb family rule may cover them all.

4. For each group, check whether the existing allow/defer/deny rules
   already match a representative sample. If they do, mark covered
   and skip — do NOT propose duplicates.

5. For groups not covered, classify them:
   - The command line itself bounds the effect — read-only, or a local
     mutation that runs no code from arguments, project files, or
     packages → ALLOW rule.
   - The command runs code (interpreters, package scripts, task or test
     runners, package executors), is destructive, mutates shared state,
     or reaches outside the local machine → no rule; it keeps deferring.
     Propose a DEFER rule only when an existing or proposed ALLOW rule
     would otherwise match it.
   - The command is unambiguously dangerous → surface for human review
     only. Do NOT auto-edit `deny.toml`.

6. Present your proposed candidates to the user as a compact table or
   numbered list. For each row include: section (allow/defer), proposed
   `name`, proposed regex, a representative sample command, the
   occurrence count, and a one-line rationale.
   Also list any covered/deny-flagged groups so the user sees the full
   picture.

7. **Iterate with the user.** They will say things like:
   - "drop #3" — remove that proposal
   - "narrow #5 — only `kubectl get`, not `kubectl logs`" — refine the regex
   - "split #7 into two rules" — propose two `[[rules]]` entries
   - "this should defer, not ALLOW" — drop it or change classification
   - "proceed" / "apply" — do the edits
   Keep iterating until the user approves. Do not edit any file until
   they say so explicitly.

8. When the user approves, **edit the TOML files directly** with the
   `Edit` tool, inserting each new rule into the appropriate Title
   Case section:
   - ALLOW additions → `src/agent_sentinel/rules/allow.toml`
   - DEFER additions → `src/agent_sentinel/rules/defer.toml`
   - Never write to `deny.toml`.

   Both files are organized into thematic sections marked with
   `# --- Title Case Section Name ---` headers (e.g. `# --- Git ---`,
   `# --- GitHub CLI ---`, `# --- Docker Mutations ---`,
   `# --- Code Execution ---`). Before
   editing, **read the target file** so you understand the current
   section layout. Then for each new rule:
   - **Match it to an existing section by topic.** A new `gh` read
     rule belongs under `# --- GitHub CLI ---` in allow.toml; a new
     destructive command carved out of an allow rule belongs under
     `# --- Destructive File / Git / Process Operations ---` in
     defer.toml; a new code runner under `# --- Code Execution ---`.
   - **Insert as a new `[[rules]]` block at the end of that section**,
     immediately before the next `# --- ... ---` header (or at EOF
     for the last section). Preserve the blank-line spacing the
     existing blocks use.
   - **If no section fits**, create a new section at a logically
     grouped position with a Title Case header. Match the style of
     existing section names: short, topical, Title Case (e.g.
     `# --- Section Name ---`). Do not invent a section for a single
     orphan rule when an adjacent section already covers the topic.
   - **Do not add dated `# Added on ...` comments.** Git history is
     the audit trail; the rule body stays clean.
   - **Do not reorder or modify existing rules.** Existing
     `[[rules]]` blocks (their `name`, `command_regex`, and order)
     must remain untouched.

   Example — appending a new `gh-pr-comment-read` rule under the
   existing `# --- GitHub CLI ---` section in `allow.toml`:
   ```toml
   # --- GitHub CLI ---

   [[rules]]
   name = "gh-read"
   command_regex = '''^\s*gh\s+(status|api|search)(\s|$)'''

   [[rules]]
   name = "gh-subcommand-read"
   command_regex = '''^\s*gh\s+\S+\s+(list|view|...)(\s|$)'''

   [[rules]]                                # ← new block inserted here
   name = "gh-pr-comment-read"
   command_regex = '''^\s*gh\s+pr\s+comment\s+(view|list)(\s|$)'''

   # --- Google Cloud ---                   # ← next section unchanged
   ```

9. Run `make check` to check the local rule evaluator and existing tests:
    ```
    make check
    ```
    If anything fails, surface the failure to the user and let them
    decide whether to refine the regex, drop the rule, or fix the
    failure. Do not silently revert edits. Keep new tests in Git only
    when the user explicitly requests them. Tests of local rule matching
    do not establish host approval or execution behavior.

10. Show the user the resulting diff:
    ```
    git diff src/agent_sentinel/rules/ tests/test_rules.py
    ```
    Ask whether to keep, revert (`git checkout -- <file>`), or refine
    further.

## Regex rules

Each `[[rules]]` regex must:
- Be anchored with `^` (Python `re.search` matches anywhere otherwise).
- Use `( |$)` (with a leading space) after the head/subcommand to
  avoid prefix overlap (e.g. `git` matching `github`).
- Be conservative — an extra host review costs tokens, while a wrong ALLOW
  skips review entirely. When unsure, leave the command unmatched.
- Avoid prefix-option clutter (`-c key=val`, `--no-pager`, `--silent`,
  `-q`, `-R`, `-j N` etc.). The matching engine strips known prefix
  options before testing patterns, so write rules against the
  prefix-free form (`^git diff( |$)`, not `^git -c \S+ diff`).

## Constraints

- Use ONLY the tools listed in `allowed-tools`. No other Bash
  commands; no editing of files outside
  `src/agent_sentinel/rules/allow.toml`,
  `src/agent_sentinel/rules/defer.toml`, and `tests/test_rules.py`.
- Do not edit `deny.toml`. DENY changes always require manual human
  review.
- If the user asks for something outside this workflow (refactoring,
  new tooling, etc.), say so and stop.
