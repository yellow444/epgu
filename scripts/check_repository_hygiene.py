#!/usr/bin/env python3
"""Fail when tracked repository files contain secrets or private artifacts.

The check is deliberately read-only and reports only rule identifiers and
repository-relative paths.  It never prints matched values or file contents.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Tuple


ROOT = Path(__file__).resolve().parents[1]
MAX_TRACKED_BYTES = 20 * 1024 * 1024
MAX_SCANNED_BYTES = 5 * 1024 * 1024

TEMPLATE_SUFFIXES = (".example", ".sample", ".template")
FORBIDDEN_SUFFIXES = (
    ".deb",
    ".exe",
    ".jks",
    ".key",
    ".keystore",
    ".msi",
    ".p12",
    ".pfx",
    ".rpm",
    ".tar.gz",
    ".tgz",
)
FORBIDDEN_ARCHIVE_NAMES = {"pycades.zip", "cryptopro.zip"}
ALLOWED_PERSONAL_CERT_FILES = {".gitignore", ".gitkeep", "readme.md"}
PUBLIC_CERTIFICATE_SUFFIXES = (".cer", ".crt", ".p7b", ".pem")

# High-confidence token formats.  Keep these intentionally narrow so sample
# documentation and ordinary identifiers do not become false positives.
TOKEN_PATTERNS: Tuple[Tuple[str, re.Pattern[bytes]], ...] = (
    ("private-key", re.compile(b"-----BEGIN " + b"(?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    ("github-token", re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("aws-access-key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("google-api-key", re.compile(rb"AIza[0-9A-Za-z_-]{35}")),
    ("pypi-token", re.compile(rb"pypi-AgEI[0-9A-Za-z_-]{40,}")),
    ("slack-token", re.compile(rb"xox[baprs]-[0-9A-Za-z-]{20,}")),
)

SECRET_ASSIGNMENT = re.compile(
    r"^\s*(?:export\s+)?"
    r"(?:api[_-]?key|apikey|client[_-]?secret|keypin|password|"
    r"private[_-]?key|refresh[_-]?token)\s*[:=]\s*(.+?)\s*$",
    re.IGNORECASE,
)
SAFE_VALUE_MARKERS = (
    "${",
    "{{",
    "}}",
    "<",
    "change-me",
    "changeme",
    "dummy",
    "example",
    "getenv",
    "os.environ",
    "placeholder",
    "replace-with",
    "replace_with",
    "replace-me",
    "sample",
    "settings.",
    "your-",
    "your_",
)
CONFIGURATION_SUFFIXES = (
    ".cfg",
    ".conf",
    ".ini",
    ".json",
    ".jsonc",
    ".properties",
    ".sh",
    ".toml",
    ".yaml",
    ".yml",
)
SECRET_FIELD_NAMES = {
    "access_token",
    "api_key",
    "apikey",
    "client_secret",
    "key_pin",
    "keypin",
    "password",
    "private_key",
    "refresh_token",
}


def _tracked_files() -> List[str]:
    """Return tracked paths from Git, including spaces losslessly."""

    result = subprocess.run(
        ["git", "ls-files", "--cached", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    return sorted(
        item.decode("utf-8", errors="surrogateescape")
        for item in result.stdout.split(b"\0")
        if item
    )


def _is_env_template(name: str) -> bool:
    lowered = name.lower()
    return lowered == ".env.example" or lowered.endswith(TEMPLATE_SUFFIXES)


def _path_violations(relative: str, size: int) -> Iterable[str]:
    lowered = relative.lower().replace("\\", "/")
    name = lowered.rsplit("/", 1)[-1]
    if (name == ".env" or name.startswith(".env.")) and not _is_env_template(name):
        yield "tracked-local-environment"
    if name.endswith(FORBIDDEN_SUFFIXES) or name in FORBIDDEN_ARCHIVE_NAMES:
        yield "tracked-private-or-vendor-artifact"
    if (
        name.endswith(PUBLIC_CERTIFICATE_SUFFIXES)
        and "/certs/public/" not in "/" + lowered
    ):
        yield "certificate-outside-public-store"
    if "/certs/personal/" in "/" + lowered and name not in ALLOWED_PERSONAL_CERT_FILES:
        yield "tracked-personal-certificate"
    if size > MAX_TRACKED_BYTES:
        yield "oversized-tracked-file"


def _looks_safe_placeholder(value: str) -> bool:
    normalized = value.strip().strip("'\"").strip().lower()
    if not normalized:
        return True
    return any(marker in normalized for marker in SAFE_VALUE_MARKERS)


def _is_configuration(relative: str) -> bool:
    name = relative.lower().replace("\\", "/").rsplit("/", 1)[-1]
    return (
        name == ".env"
        or name.startswith(".env.")
        or name.endswith(CONFIGURATION_SUFFIXES)
    )


def _content_violations(relative: str, data: bytes) -> Iterable[str]:
    for rule, pattern in TOKEN_PATTERNS:
        if pattern.search(data):
            yield rule

    if not _is_configuration(relative):
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    if relative.lower().endswith(".json"):
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            document = None
        if document is not None and _json_contains_literal_secret(document):
            yield "literal-secret-assignment"
            return
    for line in text.splitlines():
        match = SECRET_ASSIGNMENT.match(line)
        if match and not _looks_safe_placeholder(match.group(1)):
            yield "literal-secret-assignment"
            return


def _json_contains_literal_secret(value: object) -> bool:
    """Recognize direct and Postman-style secret assignments in JSON."""

    if isinstance(value, list):
        return any(_json_contains_literal_secret(item) for item in value)
    if not isinstance(value, dict):
        return False

    lowered = {str(key).lower(): item for key, item in value.items()}
    for key, item in lowered.items():
        if key in SECRET_FIELD_NAMES and isinstance(item, str):
            if not _looks_safe_placeholder(item):
                return True

    field_name = lowered.get("key", lowered.get("name"))
    field_value = lowered.get("value")
    if (
        isinstance(field_name, str)
        and field_name.lower() in SECRET_FIELD_NAMES
        and isinstance(field_value, str)
        and not _looks_safe_placeholder(field_value)
    ):
        return True
    return any(_json_contains_literal_secret(item) for item in value.values())


def main() -> int:
    violations = set()
    try:
        tracked = _tracked_files()
    except (OSError, subprocess.CalledProcessError):
        print("Repository hygiene check could not enumerate tracked files.", file=sys.stderr)
        return 2

    for relative in tracked:
        path = ROOT / relative
        try:
            if path.is_symlink():
                violations.add(("tracked-symlink-not-scanned", relative))
                continue
            size = path.stat().st_size
            for rule in _path_violations(relative, size):
                violations.add((rule, relative))
            if size <= MAX_SCANNED_BYTES:
                for rule in _content_violations(relative, path.read_bytes()):
                    violations.add((rule, relative))
        except OSError:
            violations.add(("tracked-file-unreadable", relative))

    if violations:
        print("Repository hygiene violations (contents redacted):", file=sys.stderr)
        for rule, relative in sorted(violations):
            print("- [{}] {}".format(rule, relative), file=sys.stderr)
        print("Total violations: {}".format(len(violations)), file=sys.stderr)
        return 1

    print(
        "Repository hygiene passed: {} tracked files checked; "
        "no secrets or forbidden artifacts.".format(len(tracked))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
