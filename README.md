# agent-sentinel

agent-sentinel is a safety guard for tool calls made by Claude Code and Codex. It classifies Bash commands and file operations with shared static rules into three outcomes:

- **DENY**: operations no review may approve, such as reading credentials or deleting tracked files.
- **ALLOW**: operations whose effect the command line itself bounds. The hook approves them so the host reviewer spends no tokens on them.
- **DEFER**: everything else. The hook stays silent and the host's own review decides: the Claude Code [auto mode](https://code.claude.com/docs/en/permission-modes) classifier, or Codex [auto-review](https://learn.chatgpt.com/docs/sandboxing/auto-review).

```console
$ agent-sentinel --test "git status"
ALLOW [RULE_ALLOW]: Allowed by rules: git-status
$ agent-sentinel --test "terraform apply"
DEFER [RULE_DEFER]: Matched defer rule: terraform
```

The hook is an additional guardrail, not a replacement for the host sandbox or permission system. It is designed for hosts whose deferred calls reach an automated reviewer.

## Installation

Python 3.11 or later and `uv` are required:

```bash
uv tool install git+https://github.com/tani-shi/agent-sentinel
agent-sentinel install --target claude   # or codex, all
```

The installer merges its entries into existing configuration, saves a `.bak` file beside each changed target, and removes entries that earlier versions wrote. On Claude Code it also writes `permissions.deny` entries for sensitive paths. Use `--path FILE` to override the host configuration path.

The Claude Code hook lives in user settings, which cloud sessions do not read.

Uninstalling removes agent-sentinel's hooks and its dedicated rules file while preserving other hooks and `default.rules`:

```bash
agent-sentinel uninstall --target claude   # or codex, all
```

### Codex setup

Codex requires manual trust for user-added command hooks. After installation, start a new Codex task and trust the agent-sentinel hooks in Settings > Hooks (GUI) or `/hooks` (CLI). Trust is recorded per hook definition, so you need to trust the hooks again only after their definition changes.

Recommended `config.toml`:

```toml
sandbox_mode = "workspace-write"
approval_policy = "on-request"
approvals_reviewer = "auto_review"   # or "user" to send deferred requests to a person
```

The installer does not rewrite `config.toml`, but warns about settings that weaken enforcement:

- `features.hooks = false` (or the legacy `features.codex_hooks = false`): hook DENY decisions do not run.
- `approval_policy = "never"`: deferred commands run without review.

## How it works

| Capability | Claude Code | Codex |
|---|---|---|
| Bash | PreToolUse DENY / ALLOW; `Monitor` commands too | PreToolUse DENY, PermissionRequest ALLOW, execution-rule `forbidden` |
| File operations | Read / Write / Edit: DENY for sensitive paths, otherwise DEFER; Read of an env file: masked copy | `apply_patch`: DENY for sensitive paths |
| Sensitive paths | Hook and `permissions.deny` | Hook inspection of `apply_patch` |
| Deferred calls | Auto mode classifier (a prompt in `default` mode) | Configured `approvals_reviewer` |
| Installation target | `~/.claude/settings.json` | `~/.codex/hooks.json` and `~/.codex/rules/agent-sentinel.rules` |

Each Bash segment is evaluated in this order, and the strictest outcome across segments applies (DENY > DEFER > ALLOW):

```text
RULE_DENY → deletion scope → RULE_DEFER → RULE_ALLOW → otherwise DEFER
```

"Deletion scope" is the recursive-deletion check described in [Recursive deletion](#recursive-deletion).

### Claude Code

- A hook `allow` skips the permission prompt, which in auto mode includes the classifier review. Allow rules are therefore limited to commands that do not run arbitrary code; interpreters, package scripts, `make`, and test runners defer.
- Deferred calls produce no hook output and go through Claude Code's permission flow: the classifier in auto mode, a prompt in `default` mode, and a denial where no prompt can be shown, such as `dontAsk` mode.
- File tools defer outside sensitive paths: Claude Code approves working-directory reads and edits itself, and an allow would also approve writes outside them and to its protected paths.

### Codex

Codex execution passes through several layers:

```text
sandbox
  + agent-sentinel.rules (forbidden)
  + PreToolUse (deny only)
  + PermissionRequest (static ALLOW / DENY; otherwise defer)
  + native approval → configured reviewer when deferred
```

- **Execution rules**: `agent-sentinel.rules` contains only `forbidden` rules mirroring DENY rules that a command prefix can express, so they hold even when hooks are disabled. `~/.codex/rules/default.rules` is left untouched.
- **PreToolUse**: emits only DENY decisions; everything else is deferred.
- **PermissionRequest**: when Codex creates a Bash approval request, approves ALLOW commands, repeats DENY as a fallback, and defers everything else to Codex's approval flow. With `approvals_reviewer = "auto_review"`, deferred requests reach the reviewer agent.

### Codex limitations

- A deferred PreToolUse result does not mean Codex created an approval request. Operations contained within the sandbox may run without any approval or review, so an ALLOW saves reviewer tokens only for requests that leave the sandbox.
- PermissionRequest does not identify why Codex requested approval, so an agent-sentinel ALLOW can also approve a Bash request raised by another Codex policy layer.
- PermissionRequest covers Bash only. `apply_patch` approval requests remain with Codex.
- Tools that bypass the local function-tool hook path, including Hosted WebSearch, are not inspected.

## Rules

Both hosts share these rule files:

- [`deny.toml`](src/agent_sentinel/rules/deny.toml)
- [`defer.toml`](src/agent_sentinel/rules/defer.toml): commands that must reach the host reviewer even though an allow rule would match, such as `git reset --hard` under `git-local-ops`, and every code-execution command
- [`allow.toml`](src/agent_sentinel/rules/allow.toml)

Compound Bash commands are split into segments at pipes, `&&`, `;`, substitutions, and similar boundaries, and `bash -c` scripts are evaluated by their inner commands. The strictest classification across all segments applies. Unparseable commands defer unless a deny rule matches.

### Sensitive paths

On Claude Code, Bash and file-tool calls that touch `.env`, `.ssh/`, `.aws/`, `.kube/config`, private keys, cloud credentials, package-registry credentials, and similar paths are denied. A Bash word without whitespace that is itself such a path (`cat .env`, `> ~/.ssh/config`) is denied; any other appearance in the command text, such as `--env-file=.env`, a quoted command string, or a commit message, defers to the host reviewer. For Codex `apply_patch`, agent-sentinel extracts every Add, Update, Delete, and Move target and denies the patch if any target matches, or if the targets cannot be extracted.

The Claude Code installer's `permissions.deny` entries are enforced by the host, so verify that enforcement separately.

#### Masked env file reads

On Claude Code, a Read of an env file (the `env-files` rule: `.env`, `.env.local`, `.env.stg02`, …) is redirected through PreToolUse `updatedInput` to a copy under `$TMPDIR/agent-sentinel/masked/<session>/`, so the agent can see keys and non-secret values without receiving secrets. The copy keeps the original's lines; secret values become `<masked len=N>`:

- Values of keys whose name contains a word such as `PASSWORD`, `SECRET`, `TOKEN`, `KEY`, `AUTH`, `CRED`, or `SALT`
- Values in a known credential format (AWS keys, JWTs, Slack, GitHub, Stripe and other API tokens, private keys)
- Tokens that look random (long, mixing letters and digits), and multi-line quoted values
- The userinfo, query, and fragment of URLs; the scheme, host, port, and path stay visible
- Commented-out assignments, masked like live ones, and lines that do not parse

Masking is best effort: a secret under an ordinary key name with an ordinary-looking value, such as `SMTP_LOGIN=hunter2`, stays visible.

Around the redirect:

- `.env` itself is also refused by the `Read(**/.env)` entry in `permissions.deny`, which Claude Code checks against the redirected path, so it stays protected even if the hook fails or is not installed.
- Suffixed files such as `.env.local` are guarded by the hook alone, so that templates such as `.env.example` stay readable.
- A path that resolves outside the `env-files` rule, for example through a symlink, is denied, as is any file that cannot be masked.
- Bash commands naming an env file stay denied and point the agent to Read. Codex has no equivalent redirect and keeps the deny.

### Recursive deletion

| Target | Decision |
|---|---|
| `/`, the home directory, or a temp root itself | DENY |
| Paths under a temp root, or workspace paths that do not exist yet | ALLOW |
| Anything else, including unresolvable variables or globs | DEFER |

## CLI

### Test a command

Evaluate a command with synthetic hook input, without running the hook.

```bash
agent-sentinel --test "git status"
agent-sentinel --host codex --test "terraform apply"
agent-sentinel --host codex --event PermissionRequest --test "git status"
```

`--host codex` evaluates PreToolUse by default; `--event PermissionRequest` evaluates the approval boundary. Commands that Codex PreToolUse does not block are shown as `DEFER [CODEX_NATIVE]`, a routing prediction rather than a Codex approval result.

When running as a hook, add `--explain` to the hook command to print each decision and reason to stderr.

### Inspect rules and logs

```bash
agent-sentinel rules [--kind deny|defer|allow] [--type Bash|sensitive-path] [--json]
agent-sentinel log [-n 20] [--decision allow|deny|ask|defer] [--stage STAGE] [--since 30d] [--tail] [-f] [--json]
agent-sentinel log --path
agent-sentinel audit [--since 7d] [--json]
agent-sentinel replay [--since 30d | --event EVENT_ID] [--json]
```

- `audit` detects inconsistencies between logged DENY verdicts and hook results, evaluation exceptions, installed Codex policy drift, and differences from the current evaluator. It cannot determine whether the host executed a tool or displayed an approval UI.
- `replay` re-evaluates stored inputs with the current evaluator without executing anything.

### Annotate decisions

Record false positives and missed decisions as appended events without rewriting the original:

```bash
agent-sentinel log annotate EVENT_ID --label false-positive --note "reason"
agent-sentinel log annotate EVENT_ID --label missed-deny
agent-sentinel log annotate EVENT_ID --label expected-prompt
```

## Logs

Logs are stored in `~/.local/share/agent-sentinel/logs/` on Unix and `%LOCALAPPDATA%\agent-sentinel\logs\` on Windows. Override the location with `AGENT_SENTINEL_LOG_DIR`. On Unix, directories use mode `0700` and files use mode `0600`.

Logs keep Bash commands, target paths, working directories, and session IDs verbatim so decisions can be replayed. They do not keep Write, Edit, or `apply_patch` bodies. Treat them as work data when sharing or backing them up.

## Development

```bash
make install
make check          # lint, fmt-check, typecheck, test
make update-rules   # start the Claude Code /update-rules workflow
```

Unit tests cover local classification, installation file changes, and logs. They do not establish how Codex or Claude Code handles a hook response or a generated rule; verify those in the host application.

## License

[MIT](LICENSE)
