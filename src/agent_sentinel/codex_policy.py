"""Codex execution rules and PreToolUse policy boundaries."""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass

Token = str | tuple[str, ...]


@dataclass(frozen=True)
class PrefixRule:
    source: str
    pattern: tuple[Token, ...]
    decision: str
    match: str
    not_match: str


def _prompt(source: str, pattern: tuple[Token, ...], match: str, not_match: str) -> PrefixRule:
    return PrefixRule(source, pattern, "prompt", match, not_match)


def _forbidden(source: str, pattern: tuple[Token, ...], match: str, not_match: str) -> PrefixRule:
    return PrefixRule(source, pattern, "forbidden", match, not_match)


PROMPT_RULES = (
    _prompt("ssh", ("ssh",), "ssh host", "scp file host:/tmp"),
    _prompt("systemctl", ("systemctl",), "systemctl restart app", "service app restart"),
    _prompt("crontab-edit", ("crontab", ("-e", "-r")), "crontab -e", "crontab -l"),
    _prompt(
        "terraform",
        (
            "terraform",
            ("apply", "destroy", "import", "state", "taint", "untaint", "force-unlock"),
        ),
        "terraform apply",
        "terraform plan",
    ),
    _prompt(
        "pulumi",
        ("pulumi", ("up", "destroy", "import", "cancel", "refresh")),
        "pulumi up",
        "pulumi preview",
    ),
    _prompt(
        "kubectl-mutate",
        (
            "kubectl",
            (
                "apply",
                "delete",
                "create",
                "replace",
                "patch",
                "edit",
                "rollout",
                "scale",
                "drain",
                "cordon",
                "uncordon",
                "taint",
                "untaint",
            ),
        ),
        "kubectl apply -f app.yaml",
        "kubectl get pods",
    ),
    _prompt(
        "helm-mutate",
        ("helm", ("install", "upgrade", "uninstall", "rollback")),
        "helm upgrade app chart",
        "helm list",
    ),
    _prompt("npm-publish", (("npm", "yarn", "pnpm"), "publish"), "npm publish", "npm pack"),
    _prompt("gem-push", ("gem", "push"), "gem push app.gem", "gem build app.gemspec"),
    _prompt(
        "twine-upload",
        ("twine", "upload"),
        "twine upload dist/pkg.whl",
        "twine check dist/pkg.whl",
    ),
    _prompt("uv-mutate", ("uv", ("add", "remove", "publish")), "uv add httpx", "uv sync"),
    _prompt(
        "uv-mutate", ("uv", "pip", ("install", "uninstall")), "uv pip install httpx", "uv pip list"
    ),
    _prompt(
        "uv-mutate",
        ("uv", "tool", ("install", "uninstall")),
        "uv tool install ruff",
        "uv tool run ruff",
    ),
    _prompt("uv-mutate", ("uv", "self", "update"), "uv self update", "uv self version"),
    _prompt(
        "rustup-mutate",
        (
            "rustup",
            (
                "update",
                "self",
                "install",
                "uninstall",
                "default",
                "override",
                "component",
                "target",
                "toolchain",
                "run",
            ),
        ),
        "rustup update",
        "rustup show",
    ),
    _prompt(
        "cargo-mutate",
        ("cargo", ("install", "uninstall", "add", "remove", "update", "search", "publish")),
        "cargo publish",
        "cargo test",
    ),
    _prompt(
        "docker-exec-run",
        ("docker", ("exec", "run", "cp", "login", "logout", "attach")),
        "docker run image",
        "docker ps",
    ),
    _prompt(
        "docker-compose-exec-run",
        ("docker", "compose", ("exec", "run")),
        "docker compose run app",
        "docker compose ps",
    ),
    _prompt(
        "docker-compose-exec-run",
        ("docker-compose", ("exec", "run")),
        "docker-compose run app",
        "docker-compose ps",
    ),
    _prompt("go-generate", ("go", "generate"), "go generate ./...", "go test ./..."),
    _prompt(
        "gh-mutate",
        (
            "gh",
            ("pr", "issue"),
            ("create", "close", "merge", "reopen", "edit", "comment", "review"),
        ),
        "gh pr merge 1",
        "gh pr view 1",
    ),
    _prompt(
        "gh-release",
        ("gh", "release", ("create", "delete", "edit", "upload")),
        "gh release create v1",
        "gh release view v1",
    ),
    _prompt(
        "gh-repo-mutate",
        ("gh", "repo", ("create", "delete", "fork", "rename", "archive", "edit")),
        "gh repo delete owner/repo",
        "gh repo view owner/repo",
    ),
    _prompt(
        "gh-workflow-mutate",
        ("gh", "workflow", ("run", "disable", "enable", "delete")),
        "gh workflow run ci",
        "gh workflow view ci",
    ),
    _prompt(
        "gcloud-pubsub-pull",
        ("gcloud", "pubsub", "subscriptions", "pull"),
        "gcloud pubsub subscriptions pull sub",
        "gcloud pubsub subscriptions describe sub",
    ),
    _prompt(
        "aws-s3-mutate",
        ("aws", "s3", ("cp", "mv", "rm", "sync", "mb", "rb", "website")),
        "aws s3 rm s3://bucket/key",
        "aws s3 ls",
    ),
    _prompt(
        "firebase-mutate",
        (
            "firebase",
            (
                "functions:delete",
                "firestore:delete",
                "hosting:disable",
                "database:remove",
                "database:set",
                "database:update",
                "database:push",
            ),
        ),
        "firebase functions:delete fn",
        "firebase functions:list",
    ),
    _prompt(
        "firebase-auth",
        ("firebase", ("auth:import", "auth:export")),
        "firebase auth:import users.json",
        "firebase auth:list",
    ),
    _prompt(
        "firebase-extensions",
        (
            "firebase",
            (
                "extensions:install",
                "extensions:uninstall",
                "extensions:update",
                "extensions:configure",
            ),
        ),
        "firebase extensions:install publisher/name",
        "firebase extensions:list",
    ),
    _prompt(
        "firebase-project-mutate",
        ("firebase", ("projects:addfirebase", "apps:create", "use")),
        "firebase use production",
        "firebase projects:list",
    ),
    _prompt(
        "firebase-config-mutate",
        (
            "firebase",
            ("functions:config:set", "functions:config:unset", "functions:config:clone"),
        ),
        "firebase functions:config:set key=value",
        "firebase functions:config:get",
    ),
    _prompt(
        "firebase-login",
        ("firebase", ("login", "logout")),
        "firebase login",
        "firebase projects:list",
    ),
    _prompt(
        "defaults-write",
        ("defaults", ("write", "import", "delete")),
        "defaults write domain key value",
        "defaults read domain",
    ),
    _prompt(
        "brew-mutate",
        (
            "brew",
            (
                "install",
                "uninstall",
                "upgrade",
                "reinstall",
                "link",
                "unlink",
                "tap",
                "untap",
                "cleanup",
                "autoremove",
                "pin",
                "unpin",
                "services",
            ),
        ),
        "brew install jq",
        "brew info jq",
    ),
    _prompt(
        "claude-plugins-mutate",
        ("claude", "plugin", ("update", "install", "uninstall", "remove", "add")),
        "claude plugin install example",
        "claude plugin list",
    ),
    _prompt(
        "claude-plugins-mutate",
        ("claude", "plugins", ("update", "install", "uninstall", "remove", "add")),
        "claude plugins install example",
        "claude plugins list",
    ),
    _prompt(
        "xai-config-write",
        ("xai", "config", ("init", "set")),
        "xai config set key value",
        "xai config get key",
    ),
    _prompt("fam-init", ("fam", "init"), "fam init", "fam status"),
    _prompt("fam-fetch-update", ("fam", ("fetch", "update")), "fam fetch", "fam list"),
    _prompt("fam-import", ("fam", "import"), "fam import data", "fam export data"),
    _prompt(
        "fam-config-set",
        ("fam", "config", "set"),
        "fam config set key value",
        "fam config get key",
    ),
    _prompt(
        "fam-schedule-mutate",
        ("fam", "schedule", ("enable", "disable")),
        "fam schedule enable job",
        "fam schedule list",
    ),
    _prompt(
        "fam-service-mutate",
        ("fam", "service", ("add", "remove")),
        "fam service add app",
        "fam service list",
    ),
    _prompt(
        "agent-sentinel-mutate",
        (("agent-sentinel", "claude-sentinel"), ("install", "uninstall")),
        "agent-sentinel install",
        "agent-sentinel --test ls",
    ),
    _prompt("osascript", ("osascript",), "osascript -e 'return 1'", "open app"),
    _prompt("bun-x-execute", ("bun", "x"), "bun x package", "bun test"),
    _prompt("kill", ("kill",), "kill 123", "killall app"),
    _prompt(
        "launchctl-mutate",
        (
            "launchctl",
            (
                "load",
                "unload",
                "bootstrap",
                "bootout",
                "kickstart",
                "kill",
                "enable",
                "disable",
                "start",
                "stop",
                "remove",
                "submit",
            ),
        ),
        "launchctl bootout gui/501/app",
        "launchctl list",
    ),
    _prompt(
        "xargs-destructive",
        ("xargs", ("rm", "kill", "chmod", "chown", "mv", "dd")),
        "xargs rm",
        "xargs echo",
    ),
    _prompt("eval-source", (("eval", "source", "."),), "source env.sh", "bash env.sh"),
    _prompt(
        "ntn-pages-mutate",
        ("ntn", "pages", ("create", "edit", "trash")),
        "ntn pages trash page-id",
        "ntn pages get page-id",
    ),
    _prompt(
        "ntn-files-create",
        ("ntn", "files", "create"),
        "ntn files create file",
        "ntn files get file",
    ),
    _prompt(
        "ntn-session-mutate",
        ("ntn", ("login", "logout", "update")),
        "ntn login",
        "ntn status",
    ),
    _prompt("docker-push", ("docker", "push"), "docker push image", "docker pull image"),
    _prompt("git-commit", ("git", "commit"), "git commit -m message", "git status"),
    _prompt("duti-write", ("duti", "-s"), "duti -s app ext role", "duti -x ext"),
    _prompt(
        "git-reset-hard",
        ("git", "reset", "--hard"),
        "git reset --hard HEAD",
        "git reset --soft HEAD",
    ),
    _prompt("git-checkout", ("git", "checkout"), "git checkout branch", "git switch branch"),
    _prompt("git-clean", ("git", "clean"), "git clean -fd", "git status"),
    _prompt(
        "flashspace-mutate",
        ("flashspace", ("delete", "add", "set", "create", "update", "remove")),
        "flashspace delete item",
        "flashspace list",
    ),
)


FORBIDDEN_RULES = (
    _forbidden("sudo", ("sudo",), "sudo id", "id"),
    _forbidden("watch", ("watch",), "watch date", "date"),
    _forbidden(
        "gcloud-secrets-access",
        ("gcloud", "secrets", "versions", "access"),
        "gcloud secrets versions access latest",
        "gcloud secrets versions list secret",
    ),
    _forbidden(
        "gcloud-print-token",
        ("gcloud", "auth", ("print-access-token", "print-identity-token")),
        "gcloud auth print-access-token",
        "gcloud auth login",
    ),
    _forbidden(
        "gcloud-service-account-keys",
        ("gcloud", "iam", "service-accounts", "keys", "create"),
        "gcloud iam service-accounts keys create key.json",
        "gcloud iam service-accounts keys list",
    ),
    _forbidden("ntn-auth-token", ("ntn", "auth", "token"), "ntn auth token", "ntn auth status"),
    _forbidden("pkill", ("pkill",), "pkill worker", "kill 123"),
    _forbidden("killall", ("killall",), "killall worker", "kill 123"),
    _forbidden(
        "xargs-pkill-killall",
        ("xargs", ("pkill", "killall")),
        "xargs pkill",
        "xargs echo",
    ),
)

HYBRID_ASK_RULES = {
    "docker-push",
    "git-commit",
    "duti-write",
    "git-reset-hard",
    "git-checkout",
    "git-clean",
    "flashspace-mutate",
}

NATIVE_ASK_RULES = {
    "deploy",
    "make-deploy",
    "make-sync",
    "make-publish-release",
    "make-upgrade",
    "gh-api-mutate",
    "git-push-force",
    "git-push-refspec-force",
    "git-push-delete",
    "curl-mutate",
    "curl-data",
    "gcloud-mutate",
    "aws-mutate",
    "npm-run-migrate",
    "plistbuddy-write",
    "ntn-api-mutate",
    "npx-execute",
}

HOOK_DENY_ASK_REASONS = {
    "rm-recursive": (
        "Recursive deletion requires review that a Codex hook cannot request. "
        "Run it yourself, or use `git discard --untracked <path>` for untracked files so "
        "`git discard --undo` can recover them."
    ),
    "git-restore-worktree": (
        "Restoring the worktree can destroy uncommitted work. Use `git discard "
        "[<pathspec>...]`, which snapshots the current state for `git discard --undo`, "
        "or run the restore yourself after reviewing it."
    ),
    "git-switch-force": (
        "Forced branch switching can destroy uncommitted work. Run it yourself after "
        "reviewing the worktree state."
    ),
}


def render_rules() -> str:
    lines = [
        "# Generated by agent-sentinel. User approvals belong in default.rules.",
        "# This file never grants sandbox bypass.",
        "",
    ]
    for rule in (*PROMPT_RULES, *FORBIDDEN_RULES):
        pattern = [_render_token(token) for token in rule.pattern]
        lines.extend(
            (
                "prefix_rule(",
                f"    pattern = [{', '.join(pattern)}],",
                f'    decision = "{rule.decision}",',
                f"    match = [{json.dumps(rule.match)}],",
                f"    not_match = [{json.dumps(rule.not_match)}],",
                ")",
                "",
            )
        )
    return "\n".join(lines)


def prompt_covers(source: str, command: str) -> bool:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return False
    return any(rule.source == source and _matches(rule.pattern, tokens) for rule in PROMPT_RULES)


def has_prompt_rule(source: str) -> bool:
    return any(rule.source == source for rule in PROMPT_RULES)


def _matches(pattern: tuple[Token, ...], tokens: list[str]) -> bool:
    if len(tokens) < len(pattern):
        return False
    for expected, actual in zip(pattern, tokens, strict=False):
        if isinstance(expected, tuple):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


def _render_token(token: Token) -> str:
    if isinstance(token, tuple):
        return json.dumps(list(token))
    return json.dumps(token)
