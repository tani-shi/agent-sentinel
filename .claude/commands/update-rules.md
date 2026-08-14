---
description: Interactively propose ALLOW/ASK rule additions for agent-sentinel from recent LLM_JUDGE log entries
allowed-tools: Bash(agent-sentinel log:*), Bash(agent-sentinel rules:*), Bash(make check:*), Bash(git diff:*), Read, Edit
---

You are helping the user maintain `allow.toml` and `ask.toml` for
agent-sentinel — the coding-agent safety hook that evaluates shell
commands. Find commands frequently falling through to LLM_JUDGE,
propose rules that would catch them, refine the proposals
**interactively** with the user, and then edit the rule files (and
tests) directly.

## Workflow

1. Fetch recent LLM_JUDGE log records:
   ```
   agent-sentinel log --json --stage LLM_JUDGE --since 30d -n 200
   ```
   Each record has: ts, session_id, tool_name, input, cwd, decision,
   stage, reason, elapsed_ms. The `decision` field is what the slow
   LLM judge actually picked (allow / ask / deny) — use it as a strong
   signal for classification.

2. Fetch the existing rule sets:
   ```
   agent-sentinel rules --kind allow --json
   agent-sentinel rules --kind ask --json
   agent-sentinel rules --kind deny --json
   ```

3. Group log records by *intent*, not by surface form. Examples of
   commands that should collapse to the same intent:
   - `make test 2>&1 | tail -5` and `make test`
   - `cd src && terraform apply` and `terraform apply` — focus on the
     destructive segment, not the cd
   - `cat foo | grep bar` and `grep bar foo`
   Examples of related commands worth one shared rule (a family):
   - `make test`, `make test:integration`, `make test.fast` — a single
     `make test*` family rule may cover them all.

4. For each group, check whether the existing allow/ask/deny rules
   already match a representative sample. If they do, mark covered
   and skip — do NOT propose duplicates.

5. For groups not covered, classify them:
   - LLM consistently picked `allow` and the intent is read-only or a
     pure local dev-tool invocation → ALLOW rule.
   - LLM picked `ask`, or the intent is destructive / mutates shared
     state / reaches outside the local machine → ASK rule.
   - LLM picked `deny`, or the command is unambiguously dangerous →
     surface for human review only. Do NOT auto-edit `deny.toml`.

6. Present your proposed candidates to the user as a compact table or
   numbered list. For each row include: section (allow/ask), proposed
   `name`, proposed regex, a representative sample command, the
   decision tally (e.g. `allow=12, ask=3`), and a one-line rationale.
   Also list any covered/deny-flagged groups so the user sees the full
   picture.

7. **Iterate with the user.** They will say things like:
   - "drop #3" — remove that proposal
   - "narrow #5 — only `make test:*`, not `make test.*`" — refine the regex
   - "split #7 into two rules" — propose two `[[rules]]` entries
   - "this should be ASK not ALLOW" — change classification
   - "proceed" / "apply" — do the edits
   Keep iterating until the user approves. Do not edit any file until
   they say so explicitly.

8. When the user approves, **edit the TOML files directly** with the
   `Edit` tool, inserting each new rule into the appropriate Title
   Case section:
   - ALLOW additions → `src/agent_sentinel/rules/allow.toml`
   - ASK additions → `src/agent_sentinel/rules/ask.toml`
   - Never write to `deny.toml`.

   Both files are organized into thematic sections marked with
   `# --- Title Case Section Name ---` headers (e.g. `# --- Git ---`,
   `# --- GitHub CLI ---`, `# --- Docker Mutations ---`,
   `# --- Destructive File / Git / Process Operations ---`). Before
   editing, **read the target file** so you understand the current
   section layout. Then for each new rule:
   - **Match it to an existing section by topic.** A new `gh` read
     rule belongs under `# --- GitHub CLI ---` in allow.toml; a new
     destructive command belongs under
     `# --- Destructive File / Git / Process Operations ---` in
     ask.toml; a new `make` mutation target under
     `# --- Make External-Impact Targets ---`.
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

   # --- Google Workspace CLI (gog) ---     # ← next section unchanged
   ```

9. **Add targeted tests for the new rules** by editing
   `tests/test_rules.py`:
   - For each new ALLOW rule: add an assertion in the `TestAllowRules`
     class (e.g. `assert match_allow("...") is not None`).
   - For each new ASK rule: add an assertion in the `TestAskRules`
     class.
   - Use a minimal but representative sample command. Match the style
     of the existing tests in that file.

10. Run `make check` to confirm the new rules and tests pass:
    ```
    make check
    ```
    If anything fails, surface the failure to the user and let them
    decide whether to refine the regex, drop the rule, or fix the
    test. Do not silently revert edits.

11. Show the user the resulting diff:
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
- Be conservative — better one extra ask prompt than silently allowing
  a risky command. When unsure, suggest ASK.
- Avoid prefix-option clutter (`-c key=val`, `--no-pager`, `--silent`,
  `-q`, `-R`, `-j N` etc.). The matching engine strips known prefix
  options before testing patterns, so write rules against the
  prefix-free form (`^git diff( |$)`, not `^git -c \S+ diff`).

## Constraints

- Use ONLY the tools listed in `allowed-tools`. No other Bash
  commands; no editing of files outside
  `src/agent_sentinel/rules/allow.toml`,
  `src/agent_sentinel/rules/ask.toml`, and `tests/test_rules.py`.
- Do not edit `deny.toml`. DENY changes always require manual human
  review.
- If the user asks for something outside this workflow (refactoring,
  new tooling, etc.), say so and stop.
