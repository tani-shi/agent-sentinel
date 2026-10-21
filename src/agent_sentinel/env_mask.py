"""Masked copies of `.env` files for the Claude Code Read tool.

A Read of an `env-files` path is redirected (PreToolUse ``updatedInput``) to a
copy whose secret values are replaced, so the agent sees which keys exist and
the values that are not secrets. ``permissions.deny`` is checked against the
redirected path, so the `Read(**/.env)` entry stays and still refuses a bare
`.env` when the hook fails. Suffixed files (`.env.local`) have no entry, so
templates stay readable; the hook alone guards them.

The copy keeps the original line count so Read's ``offset``/``limit`` and line
numbers refer to the same lines. Anything the parser does not understand is
masked whole.
"""

from __future__ import annotations

import os
import re
import tempfile

from agent_sentinel import paths
from agent_sentinel import rule_engine as rules

RULE_NAME = "env-files"
MAX_BYTES = 1024 * 1024

# Matched against each `_`/`-`/`.`-separated word of a key name.
_SECRET_KEY_WORDS = frozenset(
    {
        "APIKEY",
        "AUTH",
        "BEARER",
        "CERT",
        "COOKIE",
        "CRED",
        "CREDS",
        "CREDENTIAL",
        "CREDENTIALS",
        "DSN",
        "HMAC",
        "JWT",
        "KEY",
        "KEYS",
        "OTP",
        "PASS",
        "PASSPHRASE",
        "PASSWD",
        "PASSWORD",
        "PIN",
        "PRIVATE",
        "PW",
        "PWD",
        "SALT",
        "SECRET",
        "SECRETS",
        "SESSION",
        "SIGN",
        "SIGNATURE",
        "SIGNING",
        "TOKEN",
        "TOKENS",
        "WEBHOOK",
    }
)
# Also matched inside a word: `DBPASSWORD`, `GITHUBTOKEN`.
_SECRET_KEY_SUBSTRINGS = (
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "PRIVATE",
    "CREDENTIAL",
    "APIKEY",
)

_KNOWN_SECRET_VALUE = re.compile(
    r"(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"
    r"|eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]+"
    r"|xox[abposr]-"
    r"|hooks\.slack\.com/"
    r"|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_"
    r"|(sk|rk|pk)_(live|test)_|whsec_"
    r"|sk-[A-Za-z0-9_-]{16,}"
    r"|AIza[0-9A-Za-z_-]{30,}"
    r"|glpat-|npm_[A-Za-z0-9]{30,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY"
    r"|\bBearer\s"
)

_ASSIGNMENT = re.compile(r"^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.-]*)(\s*=\s*)(.*)$")
_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
# `=` before `:` so `old: DB_PASSWORD=x` is read as the DB_PASSWORD assignment.
_EMBEDDED_ASSIGNMENTS = (
    re.compile(r"(([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*)([^\s,;]+)"),
    re.compile(r"(([A-Za-z_][A-Za-z0-9_.-]*)\s*:\s*)([^\s,;]+)"),
)


class MaskError(Exception):
    """The file cannot be served masked; the Read must be denied."""


def servable(file_path: str, cwd: str) -> bool:
    """True when a Read of ``file_path`` is answered with a masked copy: the
    path, and the file it resolves to, are protected by `env-files` alone."""
    return _only_env_rule(file_path) and _only_env_rule(paths.resolve(file_path, cwd))


def _only_env_rule(path: str) -> bool:
    normalized = path.replace("\\", "/")
    hits = {
        r.name for r in rules.get_deny_rules().sensitive_path_rules if r.pattern.search(normalized)
    }
    return hits == {RULE_NAME} and rules.match_sensitive_directory(normalized) is None


def write_masked_copy(file_path: str, cwd: str, session_id: str) -> str:
    """Write the masked copy of ``file_path`` and return its path."""
    source = paths.resolve(file_path, cwd)
    if not servable(file_path, cwd):
        raise MaskError(f"{file_path} resolves outside the env-files rule")
    try:
        if not os.path.isfile(source):
            raise MaskError(f"{file_path} is not a regular file")
        if os.path.getsize(source) > MAX_BYTES:
            raise MaskError(f"{file_path} is larger than {MAX_BYTES} bytes")
        with open(source, "rb") as f:
            text = f.read().decode("utf-8", errors="replace")
    except OSError as error:
        raise MaskError(str(error)) from error

    session = re.sub(r"[^A-Za-z0-9_-]", "_", session_id or "unknown")
    base = os.path.realpath(tempfile.gettempdir())
    directory = os.path.join(base, "agent-sentinel", "masked", session)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    # The agent can plant symlinks here, so the directory must resolve to
    # itself and the copy is created exclusively under a random name: a write
    # through a link would overwrite an arbitrary file without review.
    if os.path.realpath(directory) != directory:
        raise MaskError(f"{directory} is redirected by a symlink")
    prefix = f"{os.path.basename(source).lstrip('.')}-"
    fd, target = tempfile.mkstemp(prefix=prefix, suffix=".masked", dir=directory)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(mask_text(text))
    # A copy under a protected glob would be refused by permissions.deny too.
    if rules.match_sensitive_path(target) or rules.match_sensitive_directory(target):
        os.unlink(target)
        raise MaskError(f"Masked copy path {target} is itself protected")
    return target


def mask_text(text: str) -> str:
    """Mask the secret values of `.env` content, keeping its line structure."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    while i < len(lines):
        consumed, masked = _mask_entry(lines, i)
        out.extend(masked)
        i += consumed
    return "".join(out)


def _mask_entry(lines: list[str], i: int) -> tuple[int, list[str]]:
    """Mask the entry starting at ``lines[i]``; return the lines consumed and
    their replacements."""
    line, eol = _split_eol(lines[i])
    stripped = line.strip()
    if not stripped:
        return 1, [lines[i]]
    if stripped.startswith("#"):
        return 1, [_mask_comment(line) + eol]

    m = _ASSIGNMENT.match(line)
    if not m:
        return 1, [_placeholder(line) + eol]
    prefix, key, sep, rest = m.groups()
    head = f"{prefix}{key}{sep}"

    if rest[:1] in ("'", '"'):
        quote = rest[0]
        end = _closing_quote(rest, quote)
        if end is None:
            # Multi-line quoted value: mask every line through the closing quote.
            j = i + 1
            while (
                j < len(lines) and _closing_quote(quote + _split_eol(lines[j])[0], quote) is None
            ):
                j += 1
            count = min(j + 1, len(lines)) - i
            masked = [f"{head}<masked lines={count}>{eol}"]
            masked.extend("<masked>" + _split_eol(lines[k])[1] for k in range(i + 1, i + count))
            return count, masked
        value, trailer = rest[1:end], rest[end + 1 :]
        return 1, [f"{head}{quote}{_mask_value(key, value)}{quote}{_mask_trailer(trailer)}{eol}"]

    value, trailer = _split_inline_comment(rest)
    bare = value.rstrip()
    padding = value[len(bare) :]
    return 1, [f"{head}{_mask_value(key, bare)}{padding}{_mask_trailer(trailer)}{eol}"]


def _mask_value(key: str, value: str) -> str:
    if not value:
        return value
    if _is_secret_key(key) or _KNOWN_SECRET_VALUE.search(value):
        return _placeholder(value)
    if _URL.match(value):
        return _mask_url(value)
    return _mask_random_tokens(value)


def _is_secret_key(key: str) -> bool:
    upper = key.upper()
    words = re.split(r"[_.-]+", upper)
    return any(w in _SECRET_KEY_WORDS for w in words) or any(
        s in upper for s in _SECRET_KEY_SUBSTRINGS
    )


def _mask_url(value: str) -> str:
    scheme, rest = value.split("://", 1)
    # Userinfo runs to the last `@`: a password often holds an unencoded `/`
    # or `#`, which a URL parser takes as the end of the authority.
    userinfo = "@" in rest
    rest = rest.rpartition("@")[2]
    rest, hash_, fragment = rest.partition("#")
    rest, question, query = rest.partition("?")
    host, slash, path = rest.partition("/")
    masked = f"{scheme}://{'<masked>@' if userinfo else ''}{host}{slash}"
    masked += "/".join(_mask_random_tokens(seg) for seg in path.split("/"))
    if question:
        masked += "?<masked>"
    if hash_:
        masked += "#<masked>"
    return masked


def _mask_random_tokens(text: str) -> str:
    return re.sub(r"[^\s,;]+", lambda m: _placeholder(m[0]) if _looks_random(m[0]) else m[0], text)


def _looks_random(token: str) -> bool:
    if len(token) < 16 or not re.search(r"\d", token) or not re.search(r"[A-Za-z]", token):
        return False
    if _HEX.match(token):
        return len(token) >= 32
    if token.isalnum():
        return True
    mixed_case = re.search(r"[a-z]", token) and re.search(r"[A-Z]", token)
    return bool(mixed_case) or len(token) >= 32


def _mask_comment(line: str) -> str:
    """A commented-out assignment is masked like a live one; other comment
    text only loses tokens that look like credentials."""
    body = line.lstrip().lstrip("#").lstrip()
    indent = line[: len(line) - len(body)]
    if _ASSIGNMENT.match(body):
        return indent + _mask_entry([body], 0)[1][0]
    return indent + _mask_free_text(body)


def _mask_trailer(trailer: str) -> str:
    return _mask_free_text(trailer) if trailer else trailer


def _mask_free_text(text: str) -> str:
    if _KNOWN_SECRET_VALUE.search(text):
        return _placeholder(text)
    for assignment in _EMBEDDED_ASSIGNMENTS:
        text = assignment.sub(lambda m: m[1] + _mask_value(m[2], m[3]), text)
    return _mask_random_tokens(text)


def _split_inline_comment(rest: str) -> tuple[str, str]:
    m = re.search(r"\s#", rest)
    return (rest[: m.start()], rest[m.start() :]) if m else (rest, "")


def _closing_quote(rest: str, quote: str) -> int | None:
    i = 1
    while i < len(rest):
        if quote == '"' and rest[i] == "\\":
            i += 2
            continue
        if rest[i] == quote:
            return i
        i += 1
    return None


def _split_eol(line: str) -> tuple[str, str]:
    body = line.rstrip("\r\n")
    return body, line[len(body) :]


def _placeholder(value: str) -> str:
    return f"<masked len={len(value)}>"
