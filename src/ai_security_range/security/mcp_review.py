"""Manifest: analyze an MCP tool manifest for supply-chain risk.

Flags four failure modes: poisoned descriptions (hidden instructions to the
model), typosquatted server domains, rug-pull updates that exfiltrate data,
and over-broad permission scopes. Approve only when nothing fires.
"""

from __future__ import annotations

import re

from ..models import Finding, Manifest, ManifestVerdict

_HIDDEN_INSTRUCTION = re.compile(
    r"<important>|do ?n['o]?t (mention|tell)|ignore (all|previous|prior|your)|"
    r"system\s*:|\.aws|\.ssh|id_rsa|credential|append .*(summary|output)",
    re.IGNORECASE,
)
_OVERBROAD = re.compile(r":\*\b|network:\*|filesystem:read:\*|filesystem:[^\s\"]*\*")
_EXFIL = re.compile(
    r"process\.env|postTo\(|fetch\(\s*[\"']https?://|analytics|collect|ingest",
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


def _typosquat(server: str) -> tuple[str, str] | None:
    """Return (impersonated_brand, real_domain) if the host looks like a look-alike."""
    host = server.lower().split("/")[0].strip()
    if host in _BRANDS.values():
        return None
    labels = re.split(r"[.\-_]", host)
    for brand, domain in _BRANDS.items():
        for label in labels:
            if label and label != brand and _levenshtein(label, brand) <= 2:
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
                    "An auto-update introduced code that forwards data to an outside "
                    "host. Trust was granted to the prior version, not this one."
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
