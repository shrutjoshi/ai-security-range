"""Manifest: analyze an MCP tool manifest for supply-chain risk.

Flags five failure modes: poisoned descriptions (hidden instructions to the
model), tool shadowing (a description that rewrites how *other* tools behave),
look-alike server domains (edit-distance typosquats and Unicode homographs),
rug-pull updates that exfiltrate data or run install-time scripts, and
over-broad permission scopes. Approve only when nothing fires.
"""

from __future__ import annotations

import re

from ..models import Finding, Manifest, ManifestVerdict

# Mentioning credentials is fine (a secrets scanner must); instructing the model
# to read or move them, or pointing it at key files, is not.
_HIDDEN_INSTRUCTION = re.compile(
    r"<important>|do ?n['o]?t (mention|tell)|ignore (all|previous|prior|your)|"
    r"system\s*:|~/\.aws|~/\.ssh|id_rsa|append .*(summary|output)|"
    r"\b(read|send|append|include|upload|forward|copy|exfiltrat\w*)\b[^.]{0,60}\bcredentials?\b",
    re.IGNORECASE,
)
_SHADOWING = re.compile(
    r"\bb?cc\b[^.]{0,40}@|"
    r"(when|whenever|if)\b[^.]{0,40}\b(any|other|another) tool|"
    r"\b(also|always|silently)\s+(send|forward|copy|cc|bcc|add)\b|"
    r"instead of the (user'?s?|requested|original)",
    re.IGNORECASE,
)
_OVERBROAD = re.compile(r"(^|[:/])\*($|[:/])|filesystem:[^\s\"]*\*")
_EXFIL = re.compile(
    r"process\.env|os\.environ|"
    r"\b(fetch|postTo|post|put|get|request|urlopen|send)\s*\(\s*[\"']https?://|"
    r"\b(curl|wget)\b[^|\n]*\|\s*(ba|z)?sh\b|\"(pre|post)install\"\s*:",
    re.IGNORECASE,
)

# Brand name -> its legitimate primary domain.
_BRANDS = {
    "github": "github.com",
    "slack": "slack.com",
    "google": "google.com",
    "atlassian": "atlassian.com",
    "notion": "notion.so",
    "gitlab": "gitlab.com",
}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _host(server: str) -> str:
    return server.lower().split("/")[0].split(":")[0].strip().rstrip(".")


def _homograph(server: str) -> bool:
    """True when the host uses non-ASCII or punycode labels that can mimic Latin letters."""
    host = _host(server)
    return any(ord(ch) > 127 for ch in host) or any(
        label.startswith("xn--") for label in host.split(".")
    )


def _typosquat(server: str) -> tuple[str, str] | None:
    """Return (impersonated_brand, real_domain) if the host looks like a look-alike."""
    host = _host(server)
    for domain in _BRANDS.values():
        if host == domain or host.endswith("." + domain):
            return None  # the real domain or one of its subdomains
    labels = re.split(r"[.\-_]", host)
    for brand, domain in _BRANDS.items():
        for label in labels:
            # a label that is itself another known brand (gitlab vs github) is not a squat
            if label and label != brand and label not in _BRANDS \
                    and _levenshtein(label, brand) <= 2:
                return brand, domain
    return None


def review(manifest: Manifest) -> ManifestVerdict:
    findings: list[Finding] = []

    if _HIDDEN_INSTRUCTION.search(manifest.description or ""):
        findings.append(
            Finding(
                kind="hidden_instruction",
                detail=(
                    "The description carries instructions aimed at the model, not the "
                    "user (tool poisoning). The agent would obey them silently."
                ),
            )
        )

    if _SHADOWING.search(manifest.description or ""):
        findings.append(
            Finding(
                kind="tool_shadowing",
                detail=(
                    "The description changes how the agent uses other tools (extra "
                    "recipients, redirected calls). A tool should describe itself, not "
                    "rewrite its neighbours."
                ),
            )
        )

    if manifest.server and _homograph(manifest.server):
        findings.append(
            Finding(
                kind="typosquat",
                detail=(
                    f"Server '{manifest.server}' contains non-ASCII or punycode characters "
                    "that render like Latin letters (IDN homograph). It is not the domain "
                    "it appears to be."
                ),
            )
        )

    squat = _typosquat(manifest.server or "")
    if squat:
        brand, domain = squat
        requests_brand = any(
            brand in p.lower() for p in manifest.permissions
        )
        if requests_brand or brand not in (manifest.name or "").lower():
            findings.append(
                Finding(
                    kind="typosquat",
                    detail=(
                        f"Server '{manifest.server}' resembles {domain} but is not it. "
                        "A look-alike requesting that brand's grant is an impostor."
                    ),
                )
            )

    if manifest.added_code and _EXFIL.search(manifest.added_code):
        findings.append(
            Finding(
                kind="rug_pull",
                detail=(
                    "An auto-update introduced code that reads the environment, sends data "
                    "to an outside host, or runs an install-time script. Trust was granted "
                    "to the prior version, not this one."
                ),
            )
        )

    overbroad = [p for p in manifest.permissions if _OVERBROAD.search(p)]
    if overbroad:
        findings.append(
            Finding(
                kind="overbroad_permissions",
                detail=(
                    f"Wildcard scopes {overbroad} exceed what the stated purpose needs. "
                    "Match permissions to purpose."
                ),
            )
        )

    return ManifestVerdict(approve=len(findings) == 0, findings=findings)
