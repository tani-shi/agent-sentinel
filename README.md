# agent-sentinel

agent-sentinel is a safety guard that inspects tool calls made by Claude Code and Codex. It assigns complementary responsibilities to PreToolUse hooks and permissions in Claude Code, and to the sandbox, execution rules, native approvals, and PreToolUse hooks in Codex.

agent-sentinel does not expand Codex permissions. It generates only `prompt` and `forbidden` execution rules, never `decision = "allow"`, which would permit execution outside the sandbox without approval. It also leaves the user's `~/.codex/rules/default.rules` untouched.

## Support matrix

| Capability | Claude Code | Codex |
|---|---|---|
| Bash | Static ALLOW / ASK / DENY rules and an LLM judge | Execution-rule `prompt` / `forbidden` decisions and deterministic hook DENY decisions |
| File operations | Read / Write / Edit | apply_patch |
| Sensitive paths | Hook and `permissions.deny` | Hook inspection of apply_patch |
| ASK | Request approval from PreToolUse | Use execution rules for prefix matches and delegate the rest to the native policy |
| Semantic LLM decisions | Claude Agent SDK | Codex auto-review when an approval request occurs |
| Installation target | `~/.claude/settings.json` | `~/.codex/hooks.json` and `~/.codex/rules/agent-sentinel.rules` |

Codex PreToolUse hooks can reliably block only deny decisions. Prefix-expressible ASK rules are therefore handled by `prompt` in `.rules`, while the hook handles static DENY rules, sensitive paths, and deterministic DENY rules that parse wrappers or arguments. The hook emits no output for decisions other than deny and does not override the Codex sandbox or approval decisions.

In Codex, agent-sentinel generates `prompt` rules for prefix-expressible ASK rules so that they trigger approval requests. When auto-review is selected, the Codex reviewer evaluates those requests. ASK rules without a generated prefix rule are delegated to Codex and reach auto-review only if Codex itself produces an approval request. Auto-review does not necessarily inspect operations that the sandbox can execute without approval.

agent-sentinel permanently blocks three kinds of ASK operations to protect against irrecoverable workspace changes:

- Recursive deletion whose scope cannot be determined
- `git restore` that overwrites the worktree
- Forced `git switch` that discards changes

agent-sentinel does not generate Codex rules for operations whose existing read/no-prompt behavior cannot be preserved by a prefix rule, such as deployment, make targets, HTTP or cloud mutations, force pushes to branches other than main/master, and remote branch deletion. These operations are delegated to the native Codex policy. The user or auto-review evaluates them if an approval request occurs, but operations contained within the sandbox may execute without semantic review. Some rules use `prompt` for the ordinary form and hook DENY for variants that cannot be expressed as prefixes. Codex CLI 0.147.0 confirms that the hook blocks these variants before an approval dialog appears.

Tools that do not pass through the local function-tool hook path, including Hosted WebSearch, are not inspected. The hook is an additional guardrail, not a replacement for the sandbox.

## Installation

Python 3.11 or later and `uv` are required.

Include the Claude extra to use the LLM judge with Claude Code:

```bash
uv tool install '.[claude]'
agent-sentinel install --target claude
```

Using agent-sentinel only with Codex does not require the Claude Agent SDK:

```bash
uv tool install .
agent-sentinel install --target codex
```

To register agent-sentinel with both hosts:

```bash
uv tool install '.[claude]'
agent-sentinel install --target all
```

The Codex installer merges into an existing `hooks.json` without replacing unrelated entries and generates a dedicated `agent-sentinel.rules` file. If a target already exists, it saves a `.bak` file beside it. After installation, start a new Codex task, inspect the agent-sentinel hook in one of the following locations, and trust it:

- Codex GUI: Settings > Hooks
- Codex CLI: `/hooks`

In the Codex GUI, a missing `/hooks` slash-command suggestion does not indicate a configuration problem. User-added command hooks require manual review and trust. Trust is recorded for the hook definition, so tasks that use the same definition do not require separate approval. Review and trust the hook again after changing its definition. The installer does not modify Codex's internal trust state.

Uninstalling removes both the hook and the dedicated rules file while preserving other hooks and `default.rules`:

```bash
agent-sentinel uninstall --target claude
agent-sentinel uninstall --target codex
agent-sentinel uninstall --target all
```

## Recommended Codex configuration

The recommended layers are `workspace-write`, `on-request`, auto-review, agent-sentinel execution rules, and the PreToolUse hook:

```toml
sandbox_mode = "workspace-write"
approval_policy = "on-request"
approvals_reviewer = "auto_review"
```

agent-sentinel does not rewrite `config.toml`. The installer warns only when it detects settings that disable safety features.

This repository distributes read-only Codex CLI permissions for development in [`.codex/rules/codex-readonly.rules`](.codex/rules/codex-readonly.rules). When opened as a trusted project, it permits review, rule validation, diagnostics, and configuration listing without approval. It does not match configuration or authentication changes, or plugin and MCP additions or removals.

- `features.hooks = false`: Hook DENY decisions do not run. If the canonical key is absent, the legacy `features.codex_hooks = false` setting also produces a warning.
- `approval_policy = "never"`: Approval requests are disabled, so native approvals and auto-review are unavailable. Because the Codex GUI may execute commands matching generated prompt rules without approval, agent-sentinel cannot guarantee ASK enforcement with this setting. Use `on-request`.

Prompt rules fail closed in Codex CLI 0.147.0, but Codex GUI 26.803.81509 executed commands matching the same rules without approval. Because the clients behave differently, do not treat `never` as a safety boundary for ASK decisions. The observed results are recorded in [issue #22](https://github.com/tani-shi/agent-sentinel/issues/22#issuecomment-5300085004).

See the official OpenAI documentation for Codex execution rules, approvals, and hooks:

- [Rules](https://learn.chatgpt.com/docs/agent-configuration/rules)
- [Agent approvals & security](https://learn.chatgpt.com/docs/agent-approvals-security)
- [Auto-review](https://learn.chatgpt.com/docs/sandboxing/auto-review)
- [Hooks](https://learn.chatgpt.com/docs/hooks)

## Decision pipeline

Claude Code evaluates decisions in this order:

```text
host JSON → RULE_DENY → deletion scope → RULE_ASK → RULE_ALLOW → LLM_JUDGE
```

In Codex, the layers operate independently and the strictest result applies:

```text
sandbox
  + agent-sentinel.rules (prompt / forbidden)
  + native approval → auto-review (when an approval request occurs and auto-review is selected)
  + PreToolUse (deny only)
```

Compound Bash commands are split into segments at pipes, `&&`, `;`, substitutions, and similar boundaries. Claude Code applies the strictest decision across all segments. The Codex hook also applies static DENY rules and hook-owned ASK rules to every segment.

Representative decisions include:

- DENY: `sudo`, recursive deletion of root or home, force pushes to main/master, access to sensitive paths, and infinite loops
- ASK / prompt: `ssh`, publishing, ordinary Git mutations, and CLIs with external effects
- ALLOW: `ls`, `git status`, builds, tests, linting, read-only cloud operations, and ordinary project-local edits

See the following files for the exact Claude Code rules:

- [`deny.toml`](src/agent_sentinel/rules/deny.toml)
- [`ask.toml`](src/agent_sentinel/rules/ask.toml)
- [`allow.toml`](src/agent_sentinel/rules/allow.toml)

### Sensitive paths

Both Bash and file tools reject `.env`, `.ssh/`, `.aws/`, `.kube/config`, private keys, cloud credentials, package-registry credentials, and similar sensitive paths. Claude Code also generates `permissions.deny` entries for defense in depth.

For Codex `apply_patch` calls, agent-sentinel extracts every Add, Update, Delete, and Move target and rejects the entire patch if any target matches a sensitive path. It also rejects patches whose target paths cannot be extracted.

Recursive deletion is allowed for paths that do not exist yet or are ignored by Git. It is rejected for tracked paths and for untracked paths that can be recovered with `git discard`. When variables or globs cannot be resolved, or the target is outside the workspace, Claude Code returns ASK and the Codex hook returns DENY.

## LLM judge

The Claude host uses the Claude Agent SDK as its judge backend. Timeouts, SDK errors, and turn-limit exhaustion fall back to ASK. Reaching the judge without the Claude extra installed also returns the SDK import error as ASK.

The Codex path does not invoke the Claude SDK or this LLM judge. When agent-sentinel or Codex produces an approval request and auto-review is selected, the Codex reviewer makes the semantic decision. Neither auto-review nor the agent-sentinel LLM judge is involved in operations that do not produce an approval request, and the hook emits no output for operations that match no static rule.

## CLI

Inspect a command without invoking the hook:

```bash
agent-sentinel --test "git status"
agent-sentinel --test "terraform apply"
agent-sentinel --host codex --test "terraform apply"
```

`--host codex` uses the same deny-only evaluation as the actual Codex hook. Commands that the hook does not block are displayed as `DEFER [CODEX_NATIVE]` and delegated to the sandbox, execution rules, and native approvals. The Codex reviewer evaluates them only when an approval request occurs and auto-review is selected. The Claude Agent SDK is not invoked.

Inspect rules and logs with the following commands:

```bash
agent-sentinel rules
agent-sentinel rules --kind deny --json
agent-sentinel log --since 30d --json
agent-sentinel log --path
agent-sentinel audit --since 7d
agent-sentinel replay --since 30d
```

Logs are stored in `~/.local/share/agent-sentinel/logs/` on Unix and `%LOCALAPPDATA%\agent-sentinel\logs\` on Windows. Override this location with `AGENT_SENTINEL_LOG_DIR`. On Unix, directories retain mode `0700` and log files retain mode `0600`.

Schema v3 logs retain readable Bash commands, target paths, working directories, session IDs, and decision reasons so that decisions can be reproduced later. They do not retain Write or Edit bodies, apply_patch patch bodies, or complete unknown tool inputs. Logs can contain information from AI tasks, so treat them like ordinary work data when sharing or backing them up.

Each evaluation event records a unique `event_id`, the raw and normalized commands, every compound-command segment, normalization steps, matched rules, Codex execution-rule coverage, and hashes of the agent-sentinel package, rules, and hook definitions. Hook definitions and Codex execution rules are hashed separately for the package's expected content and the content read from the installation target, with `*_matches` fields reporting drift. An input SHA-256 hash supports matching identical inputs. `host` is either `claude` or `codex`; `owner` identifies the deciding layer as `hook`, `execpolicy`, or `native`.

`agent-sentinel audit` detects missed DENY decisions, ASK decisions not covered by execution rules, evaluation exceptions, installed Codex policy drift, and decision differences from the current policy. `agent-sentinel replay` reevaluates stored inputs with the current evaluator without executing commands or tools or connecting to the Claude LLM judge. Events previously owned by the LLM judge that still match no static rule are reported as incomparable.

Record false positives and missed decisions as appended annotation events without rewriting the original event:

```bash
agent-sentinel log annotate EVENT_ID --label false-positive --note "reason"
agent-sentinel log annotate EVENT_ID --label missed-deny
agent-sentinel log annotate EVENT_ID --label expected-prompt
```

When the Codex hook delegates a decision, it records `defer`, distinguishing execution-rule prompt targets as `CODEX_RULE_PROMPT` and other decisions as `CODEX_NATIVE`. At the time a PreToolUse event is recorded, the hook has not yet observed whether the host accepted its output, so every `observed_outcome`, including DENY, is `unknown`. `expected_action` describes the hook's requested behavior, while `defer` identifies the destination rather than the eventual approval result.

## Migrating from claude-sentinel

Replace the existing uv tool, then update the hook:

```bash
uv tool uninstall claude-sentinel
uv tool install '.[claude]'
agent-sentinel install --target claude
```

The legacy `claude-sentinel` CLI remains available as a compatibility alias during migration. The installer replaces legacy hook commands with the new command, and uninstall removes both forms.

- Distribution name: `agent-sentinel`
- CLI: `agent-sentinel`; the legacy name is a compatibility alias
- Python import: `agent_sentinel`
- Log environment variable: `AGENT_SENTINEL_LOG_DIR`; `CLAUDE_SENTINEL_LOG_DIR` is a legacy fallback
- Log directory: `agent-sentinel/logs`; legacy logs remain readable

## Development

```bash
make install
make check
```

Run individual checks with `make lint`, `make fmt-check`, `make typecheck`, and `make test`. Maintain rules with `make update-rules`, which starts the Claude Code `/update-rules` workflow.

```text
src/agent_sentinel/
├── cli.py
├── evaluator.py
├── codex_policy.py
├── hook_io.py
├── codex_io.py
├── installer.py
├── codex_installer.py
├── patch_paths.py
├── rule_engine.py
├── llm_judge.py
└── rules/
```
