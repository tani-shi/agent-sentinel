# agent-sentinel

agent-sentinel is a safety guard that inspects tool calls made by Claude Code and Codex. It uses hooks and permissions in Claude Code, and the sandbox, execution rules, native approvals, and hooks in Codex.

agent-sentinel never grants sandbox bypass. Its execution rules use only `prompt` and `forbidden`, and it leaves `~/.codex/rules/default.rules` untouched.

## Support matrix

| Capability | Claude Code | Codex |
|---|---|---|
| Bash | Static ALLOW / ASK / DENY rules and an LLM judge | Execution-rule `prompt` / `forbidden` decisions and deterministic hook DENY decisions |
| File operations | Read / Write / Edit | apply_patch |
| Sensitive paths | Hook and `permissions.deny` | Hook inspection of apply_patch |
| ASK | Emit `ask` from PreToolUse | Generate execution-rule `prompt` targets or defer to native policy |
| Semantic LLM decisions | Claude Agent SDK | The configured Codex reviewer when an approval request occurs |
| Installation target | `~/.claude/settings.json` | `~/.codex/hooks.json` and `~/.codex/rules/agent-sentinel.rules` |

Codex PreToolUse emits deterministic DENY decisions; it cannot request approval with `ask`. Prefix-expressible ASK rules use `prompt` in `.rules`; other ASK rules defer to native policy. A matching rule or a hook `defer` result does not establish that an approval request occurred. When Codex does request approval, `auto_review` routes eligible requests to a reviewer agent instead of the user.

For supported Codex tool calls, agent-sentinel emits DENY for three high-risk ASK patterns:

- Recursive deletion whose scope cannot be determined
- `git restore` that overwrites the worktree
- Forced `git switch` that discards changes

agent-sentinel does not generate Codex rules for operations whose existing read/no-prompt behavior cannot be preserved by a prefix rule, such as deployment, make targets, HTTP or cloud mutations, force pushes to branches other than main/master, and remote branch deletion. These operations are delegated to native Codex policy. A reviewer evaluates them only if Codex creates an approval request; operations contained within the sandbox may execute without review. Some rules use `prompt` for the ordinary form and hook DENY for variants that cannot be expressed as prefixes. In an [observed Codex GUI 26.803.81509 run](https://github.com/tani-shi/agent-sentinel/issues/22#issuecomment-5299930656), the hook blocked such a variant before an approval dialog appeared.

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

The recommended layers are `workspace-write`, `on-request`, execution rules, and hooks:

```toml
sandbox_mode = "workspace-write"
approval_policy = "on-request"
```

agent-sentinel does not rewrite `config.toml`. It warns if hooks are disabled or approval requests are unavailable.

This repository distributes read-only Codex CLI permissions for development in [`.codex/rules/codex-readonly.rules`](.codex/rules/codex-readonly.rules). When opened as a trusted project, it permits review, rule validation, diagnostics, and configuration listing without approval. It does not match configuration or authentication changes, or plugin and MCP additions or removals.

- `features.hooks = false`: Hook DENY decisions do not run. If the canonical key is absent, the legacy `features.codex_hooks = false` setting also produces a warning.
- `approval_policy = "never"`: Approval requests are disabled, so native approvals and auto-review are unavailable. In an [observed Codex GUI 26.803.81509 run](https://github.com/tani-shi/agent-sentinel/issues/22#issuecomment-5300085004), a command matching a generated `prompt` rule ran without approval. agent-sentinel cannot guarantee ASK enforcement with this setting. Use `on-request`.

See the official OpenAI documentation for Codex execution rules, approvals, and hooks:

- [Configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- [Rules](https://learn.chatgpt.com/docs/agent-configuration/rules)
- [Agent approvals & security](https://learn.chatgpt.com/docs/agent-approvals-security)
- [Auto-review](https://learn.chatgpt.com/docs/sandboxing/auto-review)
- [Hooks](https://learn.chatgpt.com/docs/hooks)

For Claude Code hook decisions and permission precedence, see its [hooks reference](https://code.claude.com/docs/en/hooks) and [permissions guide](https://code.claude.com/docs/en/permissions).

## Decision pipeline

Claude Code evaluates decisions in this order:

```text
host JSON → RULE_DENY → deletion scope → RULE_ASK → RULE_ALLOW → LLM_JUDGE
```

Codex execution also depends on these layers:

```text
sandbox
  + agent-sentinel.rules (prompt / forbidden)
  + native approval → configured reviewer
  + PreToolUse (deny only)
```

Compound Bash commands are split into segments at pipes, `&&`, `;`, substitutions, and similar boundaries. The evaluator applies its strictest classification across all segments. For supported Codex tool calls, the hook emits DENY for matching static DENY rules and for ASK variants it cannot delegate to a generated prompt rule.

See the following files for the exact Claude Code rules:

- [`deny.toml`](src/agent_sentinel/rules/deny.toml)
- [`ask.toml`](src/agent_sentinel/rules/ask.toml)
- [`allow.toml`](src/agent_sentinel/rules/allow.toml)

### Sensitive paths

The Claude Code Bash and file-tool evaluator returns DENY for `.env`, `.ssh/`, `.aws/`, `.kube/config`, private keys, cloud credentials, package-registry credentials, and similar sensitive paths. The installer also writes `permissions.deny` entries. Verify host enforcement separately.

For Codex `apply_patch` calls, agent-sentinel extracts every Add, Update, Delete, and Move target and emits DENY if any target matches a sensitive path. It also emits DENY when target paths cannot be extracted.

The local evaluator classifies recursive deletion of paths that do not exist yet or are ignored by Git as ALLOW. It classifies tracked paths as DENY, with `git rm -r` as the guided alternative, and untracked paths as DENY, with `trash` as the guided alternative. When variables or globs cannot be resolved, or the target is outside the workspace, the Claude Code path returns ASK and the Codex hook emits DENY.

## LLM judge

The Claude host uses the Claude Agent SDK as its judge backend. Timeouts, SDK errors, and turn-limit exhaustion fall back to ASK. Reaching the judge without the Claude extra installed also returns the SDK import error as ASK.

The Codex path does not invoke the Claude SDK or this LLM judge. Codex routes approval requests it creates to the configured reviewer. No reviewer is involved when Codex creates no approval request, and the hook emits no output for operations that match no static rule.

## CLI

Inspect a command without invoking the hook:

```bash
agent-sentinel --test "git status"
agent-sentinel --test "terraform apply"
agent-sentinel --host codex --test "terraform apply"
```

`--host codex` uses the same deny-only evaluation as the actual Codex hook. Commands that the hook does not block are displayed as `DEFER [CODEX_RULE_PROMPT]` when a generated prefix rule matches, or `DEFER [CODEX_NATIVE]` otherwise. These labels describe agent-sentinel's routing prediction, not a Codex approval result. The Claude Agent SDK is not invoked.

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

Each evaluation event records a unique `event_id`, the raw and normalized commands, every compound-command segment, normalization steps, matched rules, whether the command matches a generated Codex execution rule, and hashes of the agent-sentinel package, rules, and hook definitions. Hook definitions and Codex execution rules are hashed separately for the package's expected content and the content read from the installation target, with `*_matches` fields reporting drift. An input SHA-256 hash supports matching identical inputs. `host` is either `claude` or `codex`; `owner` is `hook` for a hook decision and identifies an expected next policy layer (`execpolicy` or `native`) for a deferred decision.

`agent-sentinel audit` detects inconsistencies between logged DENY verdicts and hook results, ASK classifications without matching generated execution rules, evaluation exceptions, installed Codex policy drift, and differences from the current evaluator. It cannot determine whether Codex executed a tool or displayed an approval UI. `agent-sentinel replay` reevaluates stored inputs with the current evaluator without executing commands or tools or connecting to the Claude LLM judge. Events previously owned by the LLM judge that still match no static rule are reported as incomparable.

Record false positives and missed decisions as appended annotation events without rewriting the original event:

```bash
agent-sentinel log annotate EVENT_ID --label false-positive --note "reason"
agent-sentinel log annotate EVENT_ID --label missed-deny
agent-sentinel log annotate EVENT_ID --label expected-prompt
```

When the Codex hook delegates a decision, it records `defer`, distinguishing commands that match generated prompt rules as `CODEX_RULE_PROMPT` and other decisions as `CODEX_NATIVE`. These are predictions from the local classifier. At the time a PreToolUse event is recorded, the hook has not observed whether Codex accepted its output, created an approval request, or ran the tool, so every `observed_outcome`, including DENY, is `unknown`. `expected_action` is a policy expectation, not a host observation.

## Development

```bash
make install
make check
```

Run individual checks with `make lint`, `make fmt-check`, `make typecheck`, and `make test`. Maintain rules with `make update-rules`, which starts the Claude Code `/update-rules` workflow.

Unit tests cover local policy classification, installation file changes, and logs. They do not establish how Codex or Claude Code handles an approval request, a hook response, or a generated permission rule. Verify those outcomes in the host application.

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
