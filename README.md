# agent-sentinel

agent-sentinel is a safety guard for tool calls made by Claude Code and Codex. It classifies Bash commands and file operations with shared static rules, blocks dangerous operations such as reading credentials or deleting tracked files, and routes uncertain operations to an approval step.

```console
$ agent-sentinel --test "git status"
ALLOW [RULE_ALLOW]: Allowed by rules: git-status
$ agent-sentinel --test "terraform apply"
ASK [RULE_ASK]: Matched ask rule: terraform
```

The hook is an additional guardrail, not a replacement for the host sandbox or permission system.

## How it works

agent-sentinel plugs into each host through the extension points that host provides.

| Capability | Claude Code | Codex |
|---|---|---|
| Bash | Static ALLOW / ASK / DENY rules, then an LLM judge | PreToolUse DENY, PermissionRequest ALLOW, and execution-rule `prompt` / `forbidden` |
| File operations | Read / Write / Edit | `apply_patch` |
| Sensitive paths | Hook and `permissions.deny` | Hook inspection of `apply_patch` |
| ASK | `ask` from PreToolUse | Generated `prompt` execution rules, or native Codex policy |
| Semantic decisions | Claude Agent SDK | The configured Codex reviewer, when an approval request occurs |
| Installation target | `~/.claude/settings.json` | `~/.codex/hooks.json` and `~/.codex/rules/agent-sentinel.rules` |

### Claude Code

The PreToolUse hook evaluates each tool call in this order and returns the first decision:

```text
host JSON → RULE_DENY → deletion scope → RULE_ASK → RULE_ALLOW → LLM_JUDGE
```

"Deletion scope" is the recursive-deletion check described in [Recursive deletion](#recursive-deletion).

### Codex

Codex execution passes through several layers:

```text
sandbox
  + agent-sentinel.rules (prompt / forbidden)
  + PreToolUse (deny only)
  + PermissionRequest (static ALLOW / DENY; otherwise defer)
  + native approval → configured reviewer when deferred
```

- **Execution rules**: agent-sentinel generates `agent-sentinel.rules` with only `prompt` and `forbidden` decisions for ASK rules that can be expressed as command prefixes. It leaves `~/.codex/rules/default.rules` untouched.
- **PreToolUse**: Codex PreToolUse cannot request approval with `ask`, so the hook emits only deterministic DENY decisions. It denies matching static DENY rules and ASK variants that a generated prefix rule cannot express. Other commands are deferred.
- **PermissionRequest**: When Codex creates a Bash approval request, agent-sentinel evaluates the shared static rules in DENY → ASK → ALLOW order. It approves ALLOW commands, repeats PreToolUse denials as a fallback, and defers everything else to Codex's normal approval flow. With `approvals_reviewer = "auto_review"`, deferred requests reach the reviewer agent.

The Codex path never invokes the Claude Agent SDK.

### Codex limitations

- A matching rule or a deferred PreToolUse result does not mean Codex created an approval request. Operations contained within the sandbox may run without any approval or review.
- PermissionRequest does not identify why Codex requested approval, so an agent-sentinel ALLOW can also approve a Bash request raised by another Codex policy layer.
- PermissionRequest covers Bash only. `apply_patch` approval requests remain with Codex.
- Some ASK operations cannot keep their existing read/no-prompt behavior under a prefix rule, so agent-sentinel generates no rule for them and delegates them to native Codex policy. Examples include deployment, make targets, HTTP or cloud mutations, force pushes to branches other than main/master, and remote branch deletion.
- Three high-risk ASK patterns are denied outright because Codex cannot prompt for them from the hook:
  - Recursive deletion whose scope cannot be determined
  - `git restore` that overwrites the worktree
  - Forced `git switch` that discards changes
- Some rules use `prompt` for the ordinary form and hook DENY for variants that prefixes cannot express. In an [observed Codex GUI 26.803.81509 run](https://github.com/tani-shi/agent-sentinel/issues/22#issuecomment-5299930656), the hook blocked such a variant before an approval dialog appeared.
- Tools that bypass the local function-tool hook path, including Hosted WebSearch, are not inspected.

## Installation

Python 3.11 or later and `uv` are required. Clone the repository and install from its root:

```bash
git clone https://github.com/tani-shi/agent-sentinel.git
cd agent-sentinel
```

| Target | Commands |
|---|---|
| Claude Code (includes the LLM judge) | `uv tool install '.[claude]'`<br>`agent-sentinel install --target claude` |
| Codex only (no Claude Agent SDK needed) | `uv tool install .`<br>`agent-sentinel install --target codex` |
| Both | `uv tool install '.[claude]'`<br>`agent-sentinel install --target all` |

The installers merge their entries into existing configuration without replacing unrelated entries and save a `.bak` file beside each changed target. The Claude Code installer also writes `permissions.deny` entries for sensitive paths. Use `--path FILE` to override the host configuration path.

Uninstalling removes agent-sentinel's hooks and its dedicated rules file while preserving other hooks and `default.rules`:

```bash
agent-sentinel uninstall --target claude   # or codex, all
```

## Codex setup

### Trust the hooks

Codex requires manual review and trust for user-added command hooks. After installation, start a new Codex task and trust the agent-sentinel hooks in one of these locations:

- Codex GUI: Settings > Hooks
- Codex CLI: `/hooks`

A missing `/hooks` slash-command suggestion in the Codex GUI does not indicate a configuration problem. Trust is recorded per hook definition, so you need to trust the hook again only after its definition changes. The installer does not modify Codex's trust state.

### Recommended configuration

```toml
sandbox_mode = "workspace-write"
approval_policy = "on-request"
approvals_reviewer = "auto_review"
```

Set `approvals_reviewer = "user"` to send deferred requests to a person instead.

agent-sentinel does not rewrite `config.toml`, but the installer warns about settings that weaken enforcement:

- `features.hooks = false`: Hook DENY decisions do not run. If the canonical key is absent, the legacy `features.codex_hooks = false` also triggers the warning.
- `approval_policy = "never"`: Approval requests are disabled, so native approvals and auto-review are unavailable. In an [observed Codex GUI 26.803.81509 run](https://github.com/tani-shi/agent-sentinel/issues/22#issuecomment-5300085004), a command matching a generated `prompt` rule ran without approval. agent-sentinel cannot guarantee ASK enforcement with this setting.

Official references:

- Codex: [Configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference), [Rules](https://learn.chatgpt.com/docs/agent-configuration/rules), [Agent approvals & security](https://learn.chatgpt.com/docs/agent-approvals-security), [Auto-review](https://learn.chatgpt.com/docs/sandboxing/auto-review), [Hooks](https://learn.chatgpt.com/docs/hooks)
- Claude Code: [Hooks reference](https://code.claude.com/docs/en/hooks), [Permissions guide](https://code.claude.com/docs/en/permissions)

## Rules

Both hosts share these rule files:

- [`deny.toml`](src/agent_sentinel/rules/deny.toml)
- [`ask.toml`](src/agent_sentinel/rules/ask.toml)
- [`allow.toml`](src/agent_sentinel/rules/allow.toml)

Compound Bash commands are split into segments at pipes, `&&`, `;`, substitutions, and similar boundaries. The strictest classification across all segments applies.

### Sensitive paths

On Claude Code, Bash and file-tool calls that touch `.env`, `.ssh/`, `.aws/`, `.kube/config`, private keys, cloud credentials, package-registry credentials, and similar paths are denied. For Codex `apply_patch`, agent-sentinel extracts every Add, Update, Delete, and Move target and denies the patch if any target matches, or if the targets cannot be extracted.

The Claude Code installer's `permissions.deny` entries are enforced by the host, so verify that enforcement separately.

### Recursive deletion

| Target | Decision |
|---|---|
| Paths that do not exist yet or are ignored by Git | ALLOW |
| Tracked paths | DENY, suggesting `git rm -r` |
| Untracked paths | DENY, suggesting `trash` |
| Unresolvable variables or globs, or targets outside the workspace | ASK on Claude Code, DENY on Codex |

## LLM judge

On Claude Code, Bash commands that match no static rule go to an LLM judge backed by the Claude Agent SDK. Timeouts, SDK errors, turn-limit exhaustion, and a missing Claude extra all fall back to ASK.

To skip the judge and return ASK for unmatched commands, add `--judge disabled` to the hook command (`agent-sentinel --host claude --judge disabled`). Codex defaults to `disabled`; its semantic decisions come from the configured Codex reviewer.

## CLI

### Test a command

Evaluate a command with synthetic hook input, without running the hook. The LLM judge is not invoked for `--host codex`.

```bash
agent-sentinel --test "git status"
agent-sentinel --host codex --test "terraform apply"
agent-sentinel --host codex --event PermissionRequest --test "git status"
```

`--host codex` evaluates PreToolUse by default; `--event PermissionRequest` evaluates the approval boundary. Commands that Codex PreToolUse does not block are shown as one of these routing predictions, not Codex approval results:

- `DEFER [CODEX_RULE_PROMPT]`: a generated prefix rule matches, so Codex execution rules apply.
- `DEFER [CODEX_NATIVE]`: no generated rule matches, so native Codex policy applies.

When running as a hook, add `--explain` to the hook command to print each decision and reason to stderr.

### Inspect rules and logs

```bash
agent-sentinel rules [--kind deny|ask|allow] [--type Bash|sensitive-path] [--json]
agent-sentinel log [-n 20] [--decision allow|deny|ask|defer] [--stage STAGE] [--since 30d] [--tail] [-f] [--json]
agent-sentinel log --path
agent-sentinel audit [--since 7d] [--json]
agent-sentinel replay [--since 30d | --event EVENT_ID] [--json]
```

- `audit` detects inconsistencies between logged DENY verdicts and hook results, ASK classifications without matching generated execution rules, evaluation exceptions, installed Codex policy drift, and differences from the current evaluator. It cannot determine whether Codex executed a tool or displayed an approval UI.
- `replay` re-evaluates stored inputs with the current evaluator without executing anything or calling the LLM judge. Events previously decided by the LLM judge that still match no static rule are reported as incomparable.

### Annotate decisions

Record false positives and missed decisions as appended events without rewriting the original:

```bash
agent-sentinel log annotate EVENT_ID --label false-positive --note "reason"
agent-sentinel log annotate EVENT_ID --label missed-deny
agent-sentinel log annotate EVENT_ID --label expected-prompt
```

## Logs

Logs are stored in `~/.local/share/agent-sentinel/logs/` on Unix and `%LOCALAPPDATA%\agent-sentinel\logs\` on Windows. Override the location with `AGENT_SENTINEL_LOG_DIR`. On Unix, directories use mode `0700` and files use mode `0600`.

Schema v3 logs retain readable Bash commands, target paths, working directories, session IDs, and decision reasons so decisions can be reproduced. They do not retain Write or Edit bodies, `apply_patch` bodies, or complete unknown tool inputs. Treat logs like ordinary work data when sharing or backing them up.

Each evaluation event records:

- A unique `event_id` and an input SHA-256 hash for matching identical inputs
- The raw and normalized command, every compound-command segment, and normalization steps
- Matched rules and whether the command matches a generated Codex execution rule
- Hashes of the package, rules, and hook definitions. Hook definitions and Codex execution rules are hashed both as expected and as read from the installation target; `*_matches` fields report drift.
- `host`: `claude` or `codex`
- `owner`: `hook` when the hook decided, or the expected next policy layer for a deferred decision (`execpolicy` for generated execution rules, `native` for native Codex policy)
- `decision`: Codex PreToolUse records `deny` or `defer`; PermissionRequest records `allow`, `deny`, or `defer` with its event phase

Hooks cannot observe whether the host honored a response or ran the tool, so `observed_outcome` is always `unknown` and `expected_action` is a policy expectation.

## Development

```bash
make install
make check   # lint, fmt-check, typecheck, test
```

Maintain rules with `make update-rules`, which starts the Claude Code `/update-rules` workflow.

Unit tests cover local policy classification, installation file changes, and logs. They do not establish how Codex or Claude Code handles an approval request, a hook response, or a generated rule; verify those in the host application.

[`.codex/rules/codex-readonly.rules`](.codex/rules/codex-readonly.rules) lets Codex CLI run review, rule validation, diagnostics, and configuration listing without approval when this repository is opened as a trusted project. It does not match configuration or authentication changes, or plugin and MCP additions or removals.

```text
src/agent_sentinel/
├── cli.py                # CLI entry point and hook runner
├── evaluator.py          # Decision pipeline
├── rule_engine.py        # Static rule matching
├── command_normalizer.py # Prefix-option and wrapper stripping for rule matching
├── deletion_scope.py     # Recursive-deletion classification
├── git_probe.py          # Read-only Git tracked/ignored queries
├── patch_paths.py        # apply_patch target extraction
├── llm_judge.py          # Claude Agent SDK judge
├── hook_io.py            # Claude Code hook protocol
├── codex_io.py           # Codex hook protocol
├── codex_policy.py       # Codex execution rules and PreToolUse boundaries
├── installer.py          # Claude Code installer
├── codex_installer.py    # Codex installer
├── logger.py             # Log writing
├── log_event.py          # Log event schema
├── log_analysis.py       # audit and replay
├── policy_snapshot.py    # Package, rule, and hook hashes
├── paths.py              # Path resolution and containment checks
└── rules/
```
