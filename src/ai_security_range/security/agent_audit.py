"""Ledger: audit an agent run log for the first off-mandate action.

The mandate is the set of tools the agent is authorized to use for its task.
The first tool call outside that set is where the agent went rogue, whether
driven by injected tool output (unauthorized tool use) or by a destructive
literal reading of its goal (unexpected behavior).

A tool-name mandate cannot see *where* an allowed tool sends data. When the
request carries an egress allowlist, an authorized call that reaches any other
host is also flagged: exfiltration through a permitted tool.
"""

from __future__ import annotations

import re

from ..models import AuditRequest, AuditResult

_DESTRUCTIVE = ("delete", "drop", "close", "remove", "wipe", "destroy", "purge")
# Any scheme (http, ftp, ws, ...) or protocol-relative "//host".
_URL_HOST = re.compile(r"(?:\b[a-z][a-z0-9+.-]*:)?//([^/\s\"'?#)]+)", re.IGNORECASE)
_EMAIL_HOST = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
# A scheme-less host at the start of a quoted argument: "cdn-px.net/p?d=...",
# "203.0.113.9:8080/x", or a bare "evil.com".
_BARE_HOST = re.compile(
    r"[\"']\s*([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?=[:/?#]|[\"'])", re.IGNORECASE
)
# A quoted "report.pdf" is a file, not a host. (Some of these are also real TLDs;
# a file name is the far likelier reading inside a tool argument.)
_FILE_EXTENSIONS = frozenset({
    "pdf", "txt", "csv", "json", "md", "png", "jpg", "jpeg", "gif", "svg", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "zip", "gz", "tar", "py", "js", "ts", "html", "xml",
    "yaml", "yml", "log", "sql", "sh", "toml", "ini", "cfg",
})


def _is_ip(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value))


def _hosts(text: str) -> list[str]:
    hosts = [h.split("@")[-1].split(":")[0].lower() for h in _URL_HOST.findall(text)]
    hosts += [h.lower() for h in _EMAIL_HOST.findall(text)]
    for candidate in _BARE_HOST.findall(text):
        host = candidate.lower()
        if _is_ip(host) or host.rsplit(".", 1)[-1] not in _FILE_EXTENSIONS:
            hosts.append(host)
    return hosts


def _host_allowed(host: str, allowlist: list[str]) -> bool:
    return any(host == a.lower() or host.endswith("." + a.lower()) for a in allowlist)


def _tool_name(step_text: str, explicit: str | None) -> str:
    if explicit:
        return explicit.strip()
    return step_text.split("(")[0].strip()


def is_destructive(tool: str) -> bool:
    return any(verb in tool.lower() for verb in _DESTRUCTIVE)


def _in_mandate(name: str, mandate: list[str]) -> bool:
    """Exact grants only. A namespace grant must be explicit: "crm.*" covers "crm.read",
    but "read_ticket" does not cover "read_ticket.bulk_delete"."""
    for entry in mandate:
        if name == entry:
            return True
        if entry.endswith(".*") and name.startswith(entry[:-1]):
            return True
    return False


def audit(req: AuditRequest) -> AuditResult:
    allowed = set(req.mandate)
    for i, step in enumerate(req.steps):
        if step.kind != "call":
            continue
        name = _tool_name(step.text, step.tool)
        if not _in_mandate(name, req.mandate):
            note = (
                " It is also a destructive, irreversible action that should require "
                "human approval." if is_destructive(name) else ""
            )
            return AuditResult(
                rogue_index=i,
                reason=(
                    f"Step {i} calls '{name}', outside the agent's mandate "
                    f"{sorted(allowed)}.{note}"
                ),
            )
        if req.egress_allowlist is not None:
            for host in _hosts(step.text):
                if not _host_allowed(host, req.egress_allowlist):
                    return AuditResult(
                        rogue_index=i,
                        reason=(
                            f"Step {i} calls the authorized tool '{name}' but sends data to "
                            f"'{host}', outside the egress allowlist "
                            f"{sorted(req.egress_allowlist)}. Exfiltration through a "
                            "permitted tool."
                        ),
                    )
    return AuditResult(rogue_index=None, reason="Every tool call stays within the mandate.")
