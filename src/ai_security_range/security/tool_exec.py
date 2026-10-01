"""Breaker: classify a pending tool call as safe or as a known injection class.

Covers command injection, SQL injection, path traversal, and SSRF to internal
or link-local addresses (including the cloud metadata endpoint). This is the
server-side, unit-tested implementation of the Breaker challenge logic.

Hosts are normalized the way resolvers and HTTP clients do before being judged,
so obfuscated forms (decimal ``2852039166``, short ``127.1``, hex/octal octets,
IPv4-mapped IPv6, scheme-less URLs) cannot slip past the check.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlparse

from ..models import ToolCall, Verdict

# Newline and carriage return separate commands just like ";" does.
_SHELL_METACHARS = re.compile(r"[;&|`$><\n\r]")
_SQL_PAYLOAD = re.compile(
    r"\bOR\b\s+\d+\s*=\s*\d+|;\s*DROP\b|\bUNION\b\s+\bSELECT\b|--",
    re.IGNORECASE,
)
_PATH_TRAVERSAL = re.compile(r"(^|[\\/])\.\.([\\/]|$)")
_ABSOLUTE_PATH = re.compile(r"^([\\/]|~|[A-Za-z]:[\\/])")

# Hostnames that always point at the local machine or a cloud metadata service.
_INTERNAL_NAMES = ("localhost", "metadata.google.internal", "metadata", "instance-data")
_INTERNAL_SUFFIXES = (".localhost", ".internal", ".local")

# Tool-name tokens that identify which injection sink a tool reaches.
_FAMILIES: tuple[tuple[str, frozenset[str]], ...] = (
    ("http", frozenset({"http", "https", "fetch", "url", "request", "requests", "webhook",
                        "curl", "browse"})),
    ("db", frozenset({"db", "sql", "query", "database", "postgres", "mysql", "sqlite"})),
    ("shell", frozenset({"shell", "exec", "run", "command", "cmd", "bash", "sh",
                         "subprocess", "system"})),
    ("fs", frozenset({"fs", "file", "files", "path", "read", "open", "readfile", "readlink",
                      "write", "writefile"})),
)


def _legacy_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Parse the inet_aton forms browsers and libc accept: 2130706433, 127.1, 0x7f.0.0.1."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums: list[int] = []
    for part in parts:
        try:
            if part.lower().startswith("0x"):
                nums.append(int(part, 16))
            elif len(part) > 1 and part.startswith("0"):
                nums.append(int(part, 8))
            else:
                nums.append(int(part, 10))
        except ValueError:
            return None
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (5 - len(nums)):
        return None
    value = last
    for i, n in enumerate(head):
        value += n << (24 - 8 * i)
    return ipaddress.IPv4Address(value)


def _dangerous_host(host: str) -> bool:
    """True if the host resolves to a non-public address a fetch should never reach."""
    host = host.lower().rstrip(".")
    if host in _INTERNAL_NAMES or host.endswith(_INTERNAL_SUFFIXES):
        return True
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = _legacy_ipv4(host)
    if ip is None:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_unspecified or ip.is_multicast)


def _url_host(value: str) -> str:
    v = value.strip()
    if "://" not in v:
        v = "http://" + v  # scheme-less input still reaches a host once a client adds one
    return urlparse(v).hostname or ""


def _family(tool: str) -> str:
    tokens = set(re.split(r"[^a-z0-9]+", tool.lower()))
    for family, keys in _FAMILIES:
        if tokens & keys:
            return family
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
        for raw in values:
            v = unquote(unquote(raw))  # undo single and double URL encoding of "../"
            if _PATH_TRAVERSAL.search(v):
                return Verdict(
                    safe=False,
                    attack="Path traversal",
                    reason=(
                        "'..' sequences escape the intended directory. Canonicalize the "
                        "path and confirm it stays within the allowed root."
                    ),
                )
            if _ABSOLUTE_PATH.search(v):
                return Verdict(
                    safe=False,
                    attack="Path traversal",
                    reason=(
                        "An absolute path replaces the base directory outright when joined "
                        "(os.path.join, Path /, path.resolve). Reject absolute input and "
                        "confirm the resolved path stays within the allowed root."
                    ),
                )
        return Verdict(safe=True, reason="No traversal sequences in the path.")

    if family == "http":
        for v in values:
            host = _url_host(v)
            if _dangerous_host(host):
                return Verdict(
                    safe=False,
                    attack="SSRF",
                    reason=(
                        f"URL targets internal host {host} (private, loopback, or "
                        "link-local metadata, however it is encoded). Block internal "
                        "targets and allowlist destinations."
                    ),
                )
        return Verdict(safe=True, reason="No internal or link-local target in the URL.")

    return Verdict(safe=True, reason="No known injection sink for this tool and arguments.")
