# claude-sentinel

A [Claude Code hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that evaluates tool permission requests before execution. It acts as a `PermissionRequest` hook, applying a multi-stage evaluation system to automatically allow safe commands, block dangerous ones, and defer ambiguous cases to an LLM judge.

## Installation

```bash
uv tool install .
```

Then register the hooks with Claude Code:

```bash
claude-sentinel install
```

This adds `claude-sentinel` as a `PermissionRequest` hook in `~/.claude/settings.json`. A backup (`settings.json.bak`) is created automatically.

To remove:

```bash
claude-sentinel uninstall
```

## How it works

Every Bash command and file path (Read/Write/Edit/MultiEdit) is evaluated through a multi-stage pipeline:

```
stdin JSON → RULE_DENY → RULE_ASK → RULE_ALLOW → LLM_JUDGE → stdout JSON
```

| Stage | Method | Speed | Description |
|-------|--------|-------|-------------|
| RULE_DENY | Regex deny list | Instant | Blocks known-dangerous commands (e.g. `sudo`, `rm -rf /`, `curl \| bash`) |
| RULE_ASK | Regex ask list | Instant | Prompts user confirmation for commands that need review (e.g. `ssh`, `systemctl`) |
| RULE_ALLOW | Regex allow list | Instant | Permits known-safe commands (e.g. `ls`, `git status`, `make`) |
| LLM_JUDGE | LLM judge | ~2-5s | Calls `claude -p` with haiku to evaluate ambiguous commands |

### Compound Bash commands

Bash commands are not matched as a single string. A small in-house splitter (no external dependency) walks the command, tracks quoting and escaping, and finds **every individual command** inside pipelines (`|`, `|&`), lists (`&&`, `||`, `;`, `&`, newline), command substitutions (`$(…)`, `` `…` ``), process substitutions (`<(…)`, `>(…)`), subshells (`(…)`), and parameter expansions (`${…}`). Each segment is evaluated independently against DENY → ASK → ALLOW, and the overall decision is the strictest result:

```
deny  >  ask  >  llm  >  allow
```

So `cd infra && terraform apply -auto-approve` is split into `cd infra` (allow) and `terraform apply -auto-approve` (ask), and the result is **ask** — the dangerous segment cannot be hidden behind a permissive prefix. If even one segment matches no rule, the command falls through to the LLM judge with the full original string for context.

The splitter only models what it needs to find command boundaries; constructs it does not handle (heredocs `<<EOF`, ANSI-C quoting `$'…'`, `case` statements, unbalanced quotes/parens) are deferred to the LLM judge rather than punting to the human. Before falling through, the deny regex set is run against the full command string as a defense-in-depth pre-filter, so clear-cut dangerous patterns (e.g. `sudo`, `rm -rf /`, `curl … | sh`) are blocked even when the splitter cannot tokenize the command. A parser limitation can never silently *allow* a dangerous command — it can only widen the set of commands that flow through LLM evaluation, which itself falls back to **ask** on timeout or error.

### Prefix-option normalization

Rules are matched twice for each segment: once against the original command, then against a **prefix-option-stripped** form. This lets a single rule like `^\s*git\s+(diff|status|...)` match all of `git diff`, `git -c color.ui=never diff`, `git --no-pager diff`, and `git -C /tmp/repo diff` without enumerating every wrapper. Stripping is whitelist-only — for each known program (git, npm, yarn, pnpm, bun, uv, cargo, go, make, docker, gh, kubectl, aws, gcloud) only documented prefix options like `-c`, `-C`, `--no-pager`, `--silent`, `-q`, `-R`, `-j`, `--config`, `--region` are removed. An unknown option halts stripping (safe fallback), and options after the subcommand (`git push --force`, `npm run test --silent`) are never touched. The same normalization is applied to ALLOW, ASK, and DENY matching, so prefix options cannot be used to slip past confirmation rules either.

For file tools (`Read`, `Write`, `Edit`, `MultiEdit`), sensitive path deny rules are checked. If no deny rule matches, the operation is allowed. These rules are evaluated purely by the hook and are **not** written to `settings.json`. The installer adds these tools to `permissions.allow` so Claude Code does not prompt for confirmation, while the hook dynamically blocks access to sensitive paths.

Read-only tools with no side effects (`Grep`, `Glob`, `WebFetch`, `WebSearch`, Slack read/search tools) are auto-allowed without evaluation.

Tools with external impact (e.g. Slack send/schedule/canvas tools) require user confirmation (ASK).

## Deny rules (RULE_DENY)

| Rule | Pattern |
|------|---------|
| `rm-rf-root` | `rm -rf /`, `rm -rf ~`, `rm -rf $HOME` |
| `sudo` | Any command starting with `sudo` |
| `fork-bomb` | `:(){ :\|:& };:` pattern |
| `mkfs` | `mkfs` / `mkfs.ext4` etc. |
| `dd-zero` | `dd if=/dev/zero` or `/dev/urandom` |
| `pipe-to-shell` | `curl \| bash`, `wget \| sh` |
| `force-push-main` | `git push --force` / `-f` to `main`/`master` (allows `--force-with-lease`) |
| `refspec-force-push-main` | `git push origin +main` refspec force push |
| `push-delete-main` / `refspec-delete-main` | `git push --delete origin main`, `git push origin :main` |
| `env-write` | Writing to `.env` files via `>`, `>>`, `tee` |
| `dynamic-linker-hijack` | Setting `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH` |

## Sensitive path deny rules (RULE_DENY)

Sensitive files blocked from `Read`, `Write`, `Edit`, and `MultiEdit` tools. The same patterns also deny an in-place `sed -i` / `sed --in-place` whose target file matches one of them — otherwise a bash command would be a backdoor around the protection the file tools enforce:

| Category | Rule | Pattern |
|----------|------|---------|
| Env/config | `env-files` | `.env`, `.env.*` |
| Env/config | `envrc` | `.envrc` |
| Env/config | `secrets-files` | `secrets.{yml,yaml,json,toml}` |
| Env/config | `terraform-vars` | `terraform.tfvars`, `terraform.tfvars.json` |
| SSH/keys | `ssh-dir` | `.ssh/*` |
| SSH/keys | `gnupg-dir` | `.gnupg/*` |
| SSH/keys | `private-key-files` | `*.pem`, `*.key` (excludes `*.pub.pem`) |
| SSH/keys | `keystore-files` | `*.p12`, `*.pfx`, `*.jks`, `*.keystore` |
| Cloud | `aws-dir` | `.aws/*` |
| Cloud | `gcloud-dir` | `.config/gcloud/*` |
| Cloud | `azure-dir` | `.azure/*` |
| Cloud | `credentials-json` | `credentials.json`, `client_secret.json`, `service[-_]account*.json` |
| Cloud | `terraform-rc` | `.terraformrc` |
| Container | `docker-config` | `.docker/config.json` |
| Container | `kube-config` | `.kube/config` |
| Dev tools | `netrc` | `.netrc` |
| Dev tools | `npmrc` | `.npmrc` |
| Dev tools | `pypirc` | `.pypirc` |
| Dev tools | `gh-hosts` | `.config/gh/hosts.yml` |
| Dev tools | `maven-settings` | `.m2/settings.xml` |
| Dev tools | `gradle-properties` | `.gradle/gradle.properties` |
| Dev tools | `boto-config` | `.boto`, `.s3cfg` |
| Database | `pgpass` | `.pgpass` |
| Database | `mycnf` | `.my.cnf` |
| Other | `htpasswd` | `.htpasswd` |
| Other | `vault-token` | `.vault-token` |

See [`src/claude_sentinel/rules/deny.toml`](src/claude_sentinel/rules/deny.toml) for exact regex patterns.

## Auto-allow tools (AUTO_ALLOW)

Read-only tools with no side effects are automatically allowed without rule evaluation:

- `Grep` — content search
- `Glob` — file pattern matching
- `Search` — search
- `WebFetch` — fetch web content
- `WebSearch` — web search
- `mcp__claude_ai_Slack__slack_read_*` — Slack read tools
- `mcp__claude_ai_Slack__slack_search_*` — Slack search tools

Additionally, file tools are added to `permissions.allow` and evaluated by the hook with sensitive path deny rules:

- `Read` — file reading
- `Write` — file writing
- `Edit` — file editing
- `MultiEdit` — multi-edit

## Allow rules (RULE_ALLOW)

Common development commands are auto-approved, including:

- Shell: Bash comments (`#`), shell constructs (`for`, `while`, `if`, `case`, `do`/`done`, `then`/`else`/`fi`, `esac`), `pushd`/`popd`, `zsh`/`bash`/`sh` invocations
- File operations: `ls`, `cat`, `head`, `tail`, `find`, `grep`, `cp`, `mv`, `mkdir`, `touch`, `rm` (non-recursive only; `rm -r`/`rm -rf` require confirmation), `trash`
- Git: `status`, `log`, `diff`, `add`, `commit`, `revert`, `push` (with `--force-with-lease`), etc. (destructive ops like `reset --hard`, `checkout --`, `clean` require confirmation)
- Build tools: `make` (any target; dangerous targets like `deploy`/`publish`/`release`/`push`/`upgrade`/`tf-*`/`terraform-*` are escalated to ASK), `cargo` (safe subcommands only), `go build`, `node`, `bun` (excludes `bun x`), `python`, `uv` (excludes `publish`), `pip` read (`show`/`list`/`freeze`/`check`/`search`/`config get`)
- Package managers: `npm`/`yarn`/`pnpm` (safe subcommands only, excludes `publish`; `run` allows `test`/`build`/`lint`/`cli`/etc., excludes `deploy`/`publish`/`release`/`push`); `npx`/`pnpx`/`bunx` for safe dev tools (`prettier`, `tsc`, `eslint`, `biome`, `prisma`, `vitest`, `jest`, `playwright`, `shadcn`, `next`, `vite`, etc.; unknown packages require confirmation)
- Containers: `docker` (safe subcommands only, excludes `push`; `docker compose exec`/`run` require confirmation)
- Database: `sqlite3`
- Network: `curl`/`wget` (excludes pipe-to-shell, POST/PUT/DELETE/PATCH methods, and `--data` flags)
- Cloud: `aws` read operations (`list`, `describe`, `get`, `show`, `wait`), `gcloud` read operations (including `logging read` and `logging tail`)
- macOS: `launchctl` read operations (`list`, `print`, `blame`), `plutil` read (`-p`, `-lint`), `sample` (process profiling), `defaults read`, `mdfind` (Spotlight), `log show` (unified log), `fswatch` (filesystem events), `crontab -l`, `atq`
- Process inspection: `ps`, `pgrep`, `lsof`
- Utilities: `echo`, `pwd`, `which`, `date`, `sort`, `sed` (`sed -i` on a sensitive path is denied; see below), `awk`, `tar`, `zip`, `zipinfo`, `stat`, `env`, `printenv`
- Variable assignments: `VAR='value'`, `VAR="value"`, `VAR=word` (static values only; `VAR=$(...)` is split and its inner command is evaluated independently)
- `export VAR=...` (the inner `$(...)` is split out and evaluated independently)

See [`src/claude_sentinel/rules/allow.toml`](src/claude_sentinel/rules/allow.toml) for the full list.

## Ask rules (RULE_ASK)

Commands that prompt user confirmation without LLM evaluation:

- `rm -r` / `rm -rf` / `rm --recursive` — recursive file deletion
- `git reset --hard` — discard uncommitted changes
- `git checkout -- <path>` — discard file changes
- `git clean` — delete untracked files
- `osascript` — AppleScript execution (GUI control, keystrokes)
- `docker compose exec` / `docker compose run` — arbitrary command execution in containers
- `npx` / `pnpx` / `bunx` — arbitrary package execution (safe dev tools like `prettier`, `tsc`, `eslint` are auto-allowed)
- `bun x` — arbitrary package execution
- `xargs rm` / `xargs kill` / etc. — piped destructive commands
- `eval` / `source` / `.` — indirect command execution from variables or files
- `pkill` / `killall` / `kill` — process termination
- `ssh` — remote connections
- `systemctl` — system service management
- `launchctl load` / `unload` / `bootstrap` etc. — macOS service mutations
- `crontab -e` / `crontab -r` — crontab editing/removal
- `deploy` — any command containing "deploy"
- `make deploy` / `make tf-*` / `make terraform-*` — infrastructure targets
- `make publish` / `release` / `push` — external-impact make targets (with hyphenated variants)
- `make upgrade` — upgrade targets (with hyphenated variants)
- `terraform apply` / `destroy` — infrastructure mutations
- `pulumi up` / `destroy` — infrastructure mutations
- `kubectl apply` / `delete` / `create` etc. — Kubernetes mutations
- `helm install` / `upgrade` / `uninstall` / `rollback` — Helm mutations
- `npm publish` / `cargo publish` / `uv publish` / `gem push` / `twine upload` — package publishing
- `docker push` — container registry push
- `gh pr create` / `merge` / `close`, `gh issue create`, `gh release create`, `gh repo create` etc. — GitHub mutations
- `gh api ... -X POST/PUT/DELETE/PATCH` — GitHub API mutations
- `git push --force` / `-f`, `git push origin +branch`, `git push --delete` / `origin :branch` (non-main; `--force-with-lease` is allowed)
- `curl`/`wget` with `-X POST/PUT/DELETE/PATCH` or `--data` flags — HTTP mutations
- `gcloud ... create/delete/deploy/update` etc. — Google Cloud mutations
- `aws ...` — AWS CLI (catch-all; read ops are allowed by ALLOW rules)
- `npm run`/`yarn run`/`pnpm run` with `migrate`/`migration` — database migrations
- Slack send/schedule/canvas tools (TOOL_ASK)

See [`src/claude_sentinel/rules/ask.toml`](src/claude_sentinel/rules/ask.toml) for the full list.

## CLI usage

### Hook mode (default)

Reads JSON from stdin and writes the hook response to stdout. This is how Claude Code invokes it:

```bash
echo '{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"s","cwd":"/tmp"}' | claude-sentinel
```

### Test mode

Evaluate a command without the full hook protocol:

```bash
claude-sentinel --test "ls -la"
# ALLOW [RULE_ALLOW]: Allowed by rule: ls

claude-sentinel --test "sudo rm -rf /"
# DENY [RULE_DENY]: Blocked by deny rule: rm-rf-root
```

### Debug output

Add `--explain` to print the decision reason to stderr:

```bash
claude-sentinel --test "ls -la" --explain
```

### List rules

Display all loaded rules:

```bash
claude-sentinel rules                          # Show all rules
claude-sentinel rules --kind deny              # Deny rules only
claude-sentinel rules --type Read              # Read tool rules only
claude-sentinel rules --kind deny --type Read  # Combined filter
claude-sentinel rules --json                   # JSON Lines output
```

### Hook management

```bash
claude-sentinel install    # Add hooks to ~/.claude/settings.json
claude-sentinel uninstall  # Remove hooks from ~/.claude/settings.json
```

## LLM judge (LLM_JUDGE)

When a command matches neither deny, allow, nor ask rules, `claude-sentinel` invokes:

```
claude -p "<prompt>" --model claude-haiku-4-5-20251001
```

The LLM evaluates the command and responds with `ALLOW`, `DENY`, or `ASK`. On timeout (15s) or error, the decision falls back to `ASK`, which prompts the user for manual approval.

## Project structure

```
src/claude_sentinel/
├── cli.py                # Entry point, argparse
├── evaluator.py          # Multi-stage evaluation engine
├── hook_io.py            # stdin/stdout JSON handling
├── rule_engine.py        # TOML rule loading and regex matching
├── command_normalizer.py # Strip prefix options before matching/grouping
├── llm_judge.py          # LLM_JUDGE: claude subprocess
├── applier.py            # Append validated rules to allow/ask.toml
├── logger.py             # Evaluation log writer/reader
├── installer.py          # Hook install/uninstall
└── rules/
    ├── deny.toml           # RULE_DENY patterns
    ├── allow.toml          # RULE_ALLOW patterns
    ├── ask.toml            # RULE_ASK patterns
    └── llm_prompt.txt      # LLM_JUDGE prompt template
```

Rule maintenance is driven by an interactive Claude Code slash command:

```
.claude/commands/update-rules.md  # /update-rules — interactive rule proposer
```

## Development

```bash
# Install dev dependencies (ruff, pyright, pytest)
make install

# Run all checks (lint, format, typecheck, test)
make check

# Individual targets
make lint          # Run linter (ruff check)
make lint-fix      # Run linter with auto-fix
make fmt           # Format code (ruff format)
make fmt-check     # Check code formatting
make typecheck     # Run type checker (pyright)
make test          # Run tests (pytest)
make clean         # Remove build artifacts and caches

# Rule maintenance (interactive, opens Claude Code)
make update-rules

# Test a command locally
uv run claude-sentinel --test "your-command-here"
```

### Rule maintenance workflow

When `LLM_JUDGE` fallthroughs pile up in the evaluation log, refresh `allow.toml` / `ask.toml` interactively:

1. `make update-rules` launches Claude Code in **plan mode** with the first prompt set to `/update-rules` — equivalent to running `claude --permission-mode plan -- "/update-rules"`. (You can also start `claude` yourself and type `/update-rules` manually.) The slash command is defined in `.claude/commands/update-rules.md` and drives Claude through the workflow: fetch the LLM_JUDGE log via `claude-sentinel log --json`, fetch existing rules via `claude-sentinel rules --json`, group records by *intent* (not surface form), and propose ALLOW / ASK candidates with rationale and decision tally.
2. **Iterate.** Tell Claude things like "drop #3", "narrow #5 to `make test:*`", "split #7 into two rules", "this should be ASK not ALLOW". Claude refines until you say "apply".
3. On approval Claude **edits the TOML files directly**, inserting each new rule into the appropriate `# --- Title Case Section Name ---` section of `allow.toml`/`ask.toml` (or creating a new section when none fits), and adds matching assertions to `tests/test_rules.py`. `deny.toml` is never edited automatically — DENY candidates are surfaced for manual review only.
4. Claude runs `make check` to confirm the new rules and tests pass, then shows `git diff src/claude_sentinel/rules/ tests/test_rules.py`. Revert anything you disagree with (`git checkout -- <file>`).
5. Commit the approved changes.

Lower-level pieces if you want them:

- `claude-sentinel log --stage LLM_JUDGE --since 30d -n 200 --json` — raw fallthrough records.
- `claude-sentinel rules --json` — current rule snapshot.

DENY rule additions are never applied automatically. The slash command surfaces DENY candidates so you can add them to `deny.toml` by hand.

Requires Python 3.11+ (uses `tomllib` from the standard library). The only runtime dependency is `claude-agent-sdk` (used by the LLM judge stage); the rule engine and the bash splitter have zero external dependencies.

## Platform support

Works on macOS, Linux, and Windows.

- **Sensitive path rules** match both Unix (`/`) and Windows (`\`) path separators
- **Logs** are stored in `~/.local/share/claude-sentinel/logs/` on Unix, `%LOCALAPPDATA%\claude-sentinel\logs\` on Windows (override with `CLAUDE_SENTINEL_LOG_DIR`)
- **Settings** are read from `~/.claude/settings.json` on all platforms
