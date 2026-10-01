"""Manifest: analyze an MCP tool manifest for supply-chain risk.

Flags five failure modes: poisoned descriptions (hidden instructions to the
model), tool shadowing (a description that rewrites how *other* tools behave),
look-alike server domains (edit-distance typosquats and Unicode homographs),
rug-pull updates that exfiltrate data or run install-time scripts, and
over-broad permission scopes. Approve only when nothing fires.

Text is NFKC-normalized and stripped of invisible format characters before
matching, and the presence of invisible characters in a description is itself
a finding: zero-width splitting ("<IMPO\\u200bRTANT>") is a standard evasion.
"""

from __future__ import annotations

import re
import unicodedata

from ..models import Finding, Manifest, ManifestVerdict

# Mentioning credentials is fine (a secrets scanner must); instructing the model
# to read or move them, or pointing it at key files, is not.
_HIDDEN_INSTRUCTION = re.compile(
    r"<important>|do ?n['o]?t (mention|tell)|ignore (all|previous|prior|your)|"
    r"system\s*:|append[^.\n]{0,80}?(summary|output)|"
    # key material, whatever the home-directory prefix (~, $HOME, /Users/x, %USERPROFILE%)
    r"[/\\]\.(aws|ssh|gnupg|kube|docker|netrc|git-credentials|npmrc|pypirc)\b|"
    r"\bid_(rsa|dsa|ecdsa|ed25519)\b|"
    r"\b(read|load|open|cat|send|append|attach|add|include|upload|post|forward|copy|"
    r"embed|dump|collect|transmit|exfiltrat\w*)\b[^.]{0,60}\bcredentials?\b",
    re.IGNORECASE,
)
_SHADOWING = re.compile(
    r"\bb?cc\b[^.]{0,40}@|"
    r"(when|whenever|if)\b[^.]{0,40}\b(any|other|another) tool|"
    r"\b(also|always|silently)\s+(send|forward|copy|cc|bcc|add)\b|"
    r"instead of the (user'?s?|requested|original)",
    re.IGNORECASE,
)
_OVERBROAD = re.compile(r"(^|[:/])\*($|[:/])|(network|filesystem):[^\s\"]*\*")
# Anything an update adds that reaches the network, the environment, dynamic
# code, or install hooks warrants re-review: the trust was granted to the old code.
_EXFIL = re.compile(
    r"process\.env|os\.environ|getenv\s*\(|"
    r"\b(fetch|postTo|axios(\.\w+)?|got|urlopen|sendBeacon|XMLHttpRequest)\s*\(|"
    r"\brequests\.(post|put|get|patch|request)\s*\(|\bhttps?\.request\s*\(|"
    r"\bnet\.(connect|createConnection)\s*\(|\bdns\.(resolve|lookup)\w*\s*\(|"
    r"child_process|\bsubprocess\.|\beval\s*\(|\bnew\s+Function\s*\(|\batob\s*\(|"
    r"b64decode\s*\(|Buffer\.from\([^)]{0,80}base64|"
    r"\b(curl|wget)\b[^|\n]{0,200}\|\s*(ba|z)?sh\b|\"(pre|post)?install\"\s*:",
    re.IGNORECASE,
)


# Brand name -> its legitimate primary domain. Commonly impersonated in MCP and
# OAuth phishing; extend as needed.
_BRANDS = {
    "github": "github.com",
    "gitlab": "gitlab.com",
    "slack": "slack.com",
    "google": "google.com",
    "atlassian": "atlassian.com",
    "notion": "notion.so",
    "anthropic": "anthropic.com",
    "openai": "openai.com",
    "microsoft": "microsoft.com",
    "stripe": "stripe.com",
    "dropbox": "dropbox.com",
    "salesforce": "salesforce.com",
    "amazon": "amazon.com",
}


def _clean(text: str) -> str:
    """NFKC-normalize and drop invisible format characters before matching."""
    return "".join(
        ch for ch in unicodedata.normalize("NFKC", text) if unicodedata.category(ch) != "Cf"
    )


def _has_invisible(text: str) -> bool:
    return any(unicodedata.category(ch) == "Cf" for ch in text)


def _distance(a: str, b: str) -> int:
    """Optimal string alignment distance: edits plus adjacent transpositions."""
    if a == b:
        return 0
    rows = [list(range(len(b) + 1))]
    for i in range(1, len(a) + 1):
        row = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            row[j] = min(rows[-1][j] + 1, row[j - 1] + 1, rows[-1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                row[j] = min(row[j], rows[-2][j - 2] + 1)
        rows.append(row)
    return rows[-1][-1]


def _max_distance(brand: str) -> int:
    # Short brands get a tighter bound, otherwise every 5-letter word is a "squat".
    return 1 if len(brand) <= 6 else 2


def _host(server: str) -> str:
    return server.lower().split("/")[0].split(":")[0].strip().rstrip(".")


def _homograph(value: str) -> bool:
    """True when a host or name uses non-ASCII or punycode labels that can mimic Latin."""
    host = _host(value)
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
            limit = _max_distance(brand)
            if label and label != brand and label not in _BRANDS \
                    and abs(len(label) - len(brand)) <= limit \
                    and _distance(label, brand) <= limit:
                return brand, domain
    return None


def review(manifest: Manifest) -> ManifestVerdict:
    findings: list[Finding] = []
    raw_description = manifest.description or ""
    description = _clean(raw_description)
    added_code = _clean(manifest.added_code or "")
    permissions = [_clean(p) for p in manifest.permissions]

    if _has_invisible(raw_description):
        findings.append(
            Finding(
                kind="hidden_instruction",
                detail=(
                    "The description contains invisible Unicode format characters "
                    "(zero-width or bidi controls). They hide text from reviewers and "
                    "split keywords so filters miss them."
                ),
            )
        )
    elif _HIDDEN_INSTRUCTION.search(description):
        findings.append(
            Finding(
                kind="hidden_instruction",
                detail=(
                    "The description carries instructions aimed at the model, not the "
                    "user (tool poisoning). The agent would obey them silently."
                ),
            )
        )

    if _HIDDEN_INSTRUCTION.search(description) and _has_invisible(raw_description):
        findings.append(
            Finding(
                kind="hidden_instruction",
                detail=(
                    "Once invisible characters are removed, the description carries "
                    "instructions aimed at the model (tool poisoning)."
                ),
            )
        )

    if _SHADOWING.search(description):
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

    for field, value in (("Server", manifest.server), ("Tool name", manifest.name)):
        if value and _homograph(value):
            findings.append(
                Finding(
                    kind="typosquat",
                    detail=(
                        f"{field} '{value}' contains non-ASCII or punycode characters "
                        "that render like Latin letters (homograph). It is not what it "
                        "appears to be."
                    ),
                )
            )

    squat = _typosquat(manifest.server or "")
    if squat:
        brand, domain = squat
        requests_brand = any(
            brand in p.lower() for p in permissions
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

    if added_code and _EXFIL.search(added_code):
        findings.append(
            Finding(
                kind="rug_pull",
                detail=(
                    "An auto-update introduced code that reaches the network, reads the "
                    "environment, evaluates dynamic code, or runs an install-time script. "
                    "Trust was granted to the prior version, not this one."
                ),
            )
        )

    overbroad = [p for p in permissions if _OVERBROAD.search(p)]
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
