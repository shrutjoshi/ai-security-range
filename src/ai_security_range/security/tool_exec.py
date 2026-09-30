"""Breaker: classify a pending tool call as safe or as a known injection class.

Covers command injection, SQL injection, path traversal, and SSRF to internal
or link-local addresses (including the cloud metadata endpoint). This is the
server-side, unit-tested implementation of the Breaker challenge logic.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from ..models import ToolCall, Verdict

_SHELL_METACHARS = re.compile(r"[;&|`$><]|\|\||&&|\$\(")
_SQL_PAYLOAD = re.compile(
    r"\bOR\b\s+\d+\s*=\s*\d+|;\s*DROP\b|\bUNION\b\s+\bSELECT\b|--",
    re.IGNORECASE,
)
_PATH_TRAVERSAL = re.compile(r"\.\.[\\/]")


def _dangerous_host(host: str) -> bool:
    """True if the host resolves to a non-public address a fetch should never reach."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def _family(tool: str) -> str:
    t = tool.lower()
    if any(k in t for k in ("http", "fetch", "url", "request", "webhook")):
        return "http"
    if any(k in t for k in ("db", "sql", "query", "database")):
        return "db"
    if any(k in t for k in ("shell", "exec", "run", "command", "bash", "sh")):
        return "shell"
    if any(k in t for k in ("fs", "file", "path", "read", "open")):
        return "fs"
    return "other"


def classify(call: ToolCall) -> Verdict:
    """Return a safe/unsafe verdict with the attack class and a remediation note."""
    values = list(call.args.values())
    family = _family(call.tool)

    if family == "shell":
        for v in values:
            if _SHELL_METACHARS.search(v):
                return Verdict(
                    safe=False,
                    attack="Command injection",
                    reason=(
                        "Untrusted input carries shell metacharacters that can chain a "
                        "second command. Pass an argument array and validate; never build "
                        "a shell string from input."
                    ),
                )
        return Verdict(safe=True, reason="No untrusted input reaches a shell metacharacter.")

    if family == "db":
        if call.parameterized:
            return Verdict(
                safe=True,
                reason="Values are bound as parameters, not concatenated. The safe pattern.",
            )
        for v in values:
            if _SQL_PAYLOAD.search(v):
                return Verdict(
                    safe=False,
                    attack="SQL injection",
                    reason=(
                        "Input concatenated into SQL lets the caller rewrite the query. "
                        "Use parameterized statements."
                    ),
                )
        if values:
            return Verdict(
                safe=False,
                attack="SQL injection",
                reason=(
                    "The query builds SQL from unbound input. Concatenation is unsafe "
                    "even without a visible payload; parameterize it."
                ),
            )
        return Verdict(safe=True, reason="No unbound input in the query.")

    if family == "fs":
        for v in values:
            if _PATH_TRAVERSAL.search(v):
                return Verdict(
                    safe=False,
                    attack="Path traversal",
                    reason=(
                        "'..' sequences escape the intended directory. Canonicalize the "
                        "path and confirm it stays within the allowed root."
                    ),
                )
        return Verdict(safe=True, reason="No traversal sequences in the path.")

    if family == "http":
        for v in values:
            host = urlparse(v.strip()).hostname or ""
            if _dangerous_host(host):
                return Verdict(
                    safe=False,
                    attack="SSRF",
                    reason=(
                        f"URL targets internal address {host} (private, loopback, or "
                        "link-local metadata). Block internal targets and allowlist "
                        "destinations."
                    ),
                )
        return Verdict(safe=True, reason="No internal or link-local target in the URL.")

    return Verdict(safe=True, reason="No known injection sink for this tool and arguments.")
