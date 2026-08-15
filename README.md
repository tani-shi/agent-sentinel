# agent-sentinel

Claude CodeとCodexが実行するツール呼び出しを検査する安全ガードです。Claude CodeではPreToolUse hookとpermissions、Codexではsandbox・execution rules・ネイティブ承認・PreToolUse hookを役割分担させます。

agent-sentinelはCodexの権限を広げません。生成するexecution rulesは`prompt`と`forbidden`だけで、sandbox外実行を承認なしで許可する`decision = "allow"`は生成しません。利用者の`~/.codex/rules/default.rules`にも触れません。

## 対応状況

| 機能 | Claude Code | Codex |
|---|---|---|
| Bash | 静的ALLOW / ASK / DENYとLLM judge | execution rulesのprompt / forbiddenと決定論的hook DENY |
| ファイル操作 | Read / Write / Edit | apply_patch |
| 機密パス | hookとpermissions.deny | apply_patchをhookで検査 |
| ASK | PreToolUseから承認を要求 | 前方一致はexecution rules、残りはネイティブpolicyへ委譲 |
| LLMによる意味判断 | Claude Agent SDK | 承認要求が発生した場合のCodex auto-review |
| インストール先 | `~/.claude/settings.json` | `~/.codex/hooks.json`と`~/.codex/rules/agent-sentinel.rules` |

CodexのPreToolUseはdenyだけを確実に遮断できます。そのため、前方一致で表現できるASKは`.rules`の`prompt`が担当し、hookは静的DENY、機密パス、wrapperや引数を解析する決定論的DENYを担当します。hookはdeny以外では何も出力せず、Codexのsandboxと承認判断を上書きしません。

Codexでは、前方一致で表現できるASKに`prompt`を生成して承認要求を発生させます。auto-reviewを選択している場合、その承認要求をCodexのreviewerが判断します。prefix ruleを生成しないASKはCodexへ委譲され、Codex自身が承認要求を発生させた場合にだけauto-reviewの対象になります。sandbox内で承認なしに実行できる操作をauto-reviewが常に検査するわけではありません。

agent-sentinelが独自に恒久遮断するASKは、回復不能なworkspace変更を守る次の3種類です。

- 判定範囲が確定しない再帰削除
- worktreeを上書きする`git restore`
- 変更を破棄する強制的な`git switch`

deploy、make target、HTTP・cloud mutation、main/master以外へのforce pushやremote branch削除など、prefix ruleで既存のread/no-prompt判断を保てない操作にはCodex向けのruleを生成しません。これらはCodexのネイティブpolicyへ委譲されます。承認要求が発生すればユーザーまたはauto-reviewが判断しますが、sandbox内で完結する場合は意味的レビューを経ずに実行される可能性があります。通常形を`prompt`、prefixでは表せない変形をhook DENYにする規則もあり、hookは承認画面より先に遮断されることをCodex CLI 0.147.0で確認しています。

Hosted WebSearchなど、ローカルfunction toolのhook経路を通らないツールは検査対象外です。hookは追加のguardrailであり、sandboxの代替ではありません。

## インストール

Python 3.11以上と`uv`が必要です。

Claude CodeでLLM judgeを利用する場合はClaude extraを含めます。

```bash
uv tool install '.[claude]'
agent-sentinel install --target claude
```

Codexだけで利用する場合はClaude Agent SDKをインストールする必要がありません。

```bash
uv tool install .
agent-sentinel install --target codex
```

両方へ登録する場合は次を実行します。

```bash
uv tool install '.[claude]'
agent-sentinel install --target all
```

Codex installerは既存の`hooks.json`を非破壊でmergeし、専用の`agent-sentinel.rules`を生成します。変更対象がすでに存在する場合は同じ場所へ`.bak`を保存します。インストール後はCodexで`/hooks`を開き、新しいhookを確認してtrustしてください。

削除時はhookと専用rulesファイルの両方を取り除き、他のhookと`default.rules`を保持します。

```bash
agent-sentinel uninstall --target claude
agent-sentinel uninstall --target codex
agent-sentinel uninstall --target all
```

## Codexの推奨構成

推奨する層構成は`workspace-write`、`on-request`、auto-review、agent-sentinelのexecution rules、PreToolUse hookです。

```toml
sandbox_mode = "workspace-write"
approval_policy = "on-request"
approvals_reviewer = "auto_review"
```

agent-sentinelは`config.toml`を書き換えません。installerは安全機能を無効化する設定を検出したときだけ警告します。

このリポジトリは開発時に使う読み取り専用Codex CLIの許可を[`.codex/rules/codex-readonly.rules`](.codex/rules/codex-readonly.rules)で配布します。信頼済みプロジェクトとして開いた場合、review、ルール検証、診断、設定一覧などを承認なしで実行できます。設定変更、認証変更、plugin・MCPの追加や削除には一致しません。

- `features.hooks = false`：hook DENYが動作しません。canonical keyがない場合は旧`features.codex_hooks = false`も警告対象です。
- `approval_policy = "never"`：生成したprompt ruleに一致するコマンドは承認できず失敗します。同時にネイティブ承認とauto-reviewが使われないため、Codexへ委譲した操作のうちsandbox内で完結するものは意味的レビューなしで実行される可能性があります。

`never`でもprompt ruleが自動許可されることはありません。Codex CLI 0.147.0では`approval required by policy, but AskForApproval is set to Never`としてfail-closedになることを確認しています。

Codexのexecution rules、approvals、hooksの仕様はOpenAIの公式ドキュメントを参照してください。

- [Rules](https://learn.chatgpt.com/docs/agent-configuration/rules)
- [Agent approvals & security](https://learn.chatgpt.com/docs/agent-approvals-security)
- [Auto-review](https://learn.chatgpt.com/docs/sandboxing/auto-review)
- [Hooks](https://learn.chatgpt.com/docs/hooks)

## 判定パイプライン

Claude Codeでは次の順に判定します。

```text
host JSON → RULE_DENY → deletion scope → RULE_ASK → RULE_ALLOW → LLM_JUDGE
```

Codexでは各層が独立して最も厳しい結果を採ります。

```text
sandbox
  + agent-sentinel.rules（prompt / forbidden）
  + native approval → auto-review（承認要求が発生し、auto-reviewを選択している場合）
  + PreToolUse（denyのみ）
```

複合Bashコマンドはパイプ、`&&`、`;`、substitutionなどの各segmentへ分割します。Claude Codeでは全segmentの最も厳しい結果を採用します。Codex hookもすべてのsegmentに静的DENYとhook担当のASK規則を適用します。

主な判定例は次のとおりです。

- DENY：`sudo`、rootやhomeの再帰削除、main/masterへのforce push、secret pathへのアクセス、無限loop
- ASK / prompt：`ssh`、publish、通常形のGit mutation、外部影響を持つCLI
- ALLOW：`ls`、`git status`、build・test・lint、read-onlyなcloud操作、通常のproject内編集

正確なClaude Code向けルールは以下を参照してください。

- [`deny.toml`](src/agent_sentinel/rules/deny.toml)
- [`ask.toml`](src/agent_sentinel/rules/ask.toml)
- [`allow.toml`](src/agent_sentinel/rules/allow.toml)

### 機密パス

`.env`、`.ssh/`、`.aws/`、`.kube/config`、private key、cloud credential、package registry credentialなどはBashとファイルツールの双方で拒否します。Claude Codeでは`permissions.deny`も生成して二重に保護します。

Codexの`apply_patch`ではAdd、Update、Delete、Moveの全対象パスを抽出し、一つでも機密パスに一致すればpatch全体を拒否します。対象パスを抽出できないpatchも拒否します。

再帰削除は、未作成またはGit ignoredのパスなら許可し、trackedまたは回復可能な`git discard`へ誘導できるuntrackedパスは拒否します。変数やglobを解決できない場合とworkspace外は、Claude CodeではASK、Codexではhook DENYになります。

## LLM judge

Claude hostのjudge backendはClaude Agent SDKです。timeout、SDK error、turn上限ではASKへfallbackします。Claude extraがない環境でjudgeへ到達した場合もSDK import errorをASKとして返します。

Codex経路はClaude SDKやこのLLM judgeを呼びません。agent-sentinelまたはCodexが承認要求を発生させ、auto-reviewが選択されている場合はCodexのreviewerが意味的判断を行います。承認要求が発生しない操作にはauto-reviewもagent-sentinelのLLM judgeも介入せず、静的ruleに一致しない操作にはhook出力を返しません。

## CLI

コマンドをhookなしで検査できます。

```bash
agent-sentinel --test "git status"
agent-sentinel --test "terraform apply"
agent-sentinel --host codex --test "terraform apply"
```

`--host codex`は実際のCodex hookと同じdeny-only評価を使います。hookが遮断しないコマンドは`DEFER [CODEX_NATIVE]`と表示され、sandbox、execution rules、ネイティブ承認へ委譲されます。そこで承認要求が発生し、auto-reviewが選択されている場合だけCodexのreviewerが判断します。Claude Agent SDKは呼びません。

ルールとログを確認できます。

```bash
agent-sentinel rules
agent-sentinel rules --kind deny --json
agent-sentinel log --since 30d --json
agent-sentinel log --path
```

ログはUnixでは`~/.local/share/agent-sentinel/logs/`、Windowsでは`%LOCALAPPDATA%\agent-sentinel\logs\`へ保存します。`AGENT_SENTINEL_LOG_DIR`で変更できます。

## claude-sentinelからの移行

既存のuv toolを置き換えてからhookを更新します。

```bash
uv tool uninstall claude-sentinel
uv tool install '.[claude]'
agent-sentinel install --target claude
```

移行期間中は旧CLIの`claude-sentinel`も互換aliasとして利用できます。installerは旧hook commandを新しいcommandへ置き換え、uninstallは両方を除去します。

- 配布名：`agent-sentinel`
- CLI：`agent-sentinel`。旧名は互換alias
- Python import：`agent_sentinel`
- ログ環境変数：`AGENT_SENTINEL_LOG_DIR`。旧`CLAUDE_SENTINEL_LOG_DIR`はfallback
- ログディレクトリ：`agent-sentinel/logs`。旧ログも読み取り可能

## 開発

```bash
make install
make check
```

個別には`make lint`、`make fmt-check`、`make typecheck`、`make test`を利用できます。ルール保守は`make update-rules`でClaude Codeの`/update-rules` workflowを開始します。

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
