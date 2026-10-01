"""Echo: indirect (second-order) prompt-injection detection.

The attacker never messages the agent; they plant instructions in content the
agent ingests. `evaluate` models three defenses: a naive summarizer that obeys
embedded overrides, a hardened one that only falls to instructions framed as
authority, and a defense-in-depth one (quarantine plus output redaction) that
still leaks through a markdown image the chat client fetches on render.
Returns whether the planted document leaks the secret.
"""

from __future__ import annotations

import re

from ..models import InjectionResult

# A leak request has to name the protected value; "please include the chart" is not one.
_WANTS_LEAK = re.compile(
    r"secret|passphrase|password|credential|api ?key", re.IGNORECASE
)
_OVERRIDE = re.compile(
    r"ignore|disregard|forget|override|regardless of|new instruction|instead of summar",
    re.IGNORECASE,
)
_AUTHORITY = re.compile(
    r"system\s*:|assistant\s*:|admin|owner|authoriz|developer|policy update|"
    r"-{3,}|#{2,}|\[system\]|<system>|end of document|actual task",
    re.IGNORECASE,
)
# Level 2: a markdown image whose URL the bot templates from its own context.
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)\)")
_PLACEHOLDER = re.compile(r"\{\s*(\w+)\s*\}")


def context_vars(secret: str) -> dict[str, str]:
    """Template variables SummarizeBot resolves in documents at level 2."""
    return {"user_name": "dana", "today": "2026-09-30", "api_token": secret}


def _level2(document: str, secret: str, techniques: list[str]) -> InjectionResult:
    summary = "Summary of the document."
    if _WANTS_LEAK.search(document) or _AUTHORITY.search(document) \
            or _OVERRIDE.search(document):
        return InjectionResult(
            reply="Document quarantined: it references protected data or imitates "
                  "an instruction.",
            leaked=False,
            techniques=techniques,
        )
    variables = context_vars(secret)
    fetched: list[str] = []
    for url in _MD_IMAGE.findall(document):
        fetched.append(
            _PLACEHOLDER.sub(lambda m: variables.get(m.group(1), m.group(0)), url)
        )
    if not fetched:
        return InjectionResult(reply=summary, leaked=False, techniques=techniques)
    # The output filter only scrubs prose; the image URL is rendered, then fetched.
    leaked = any(secret in url for url in fetched)
    log = "\n".join(f"[client] GET {url}" for url in fetched)
    return InjectionResult(
        reply=f"{summary} (figures preserved)\n{log}",
        leaked=leaked,
        techniques=[*techniques, "image_exfil"] if leaked else techniques,
    )


def evaluate(level: int, document: str, secret: str) -> InjectionResult:
    wants = bool(_WANTS_LEAK.search(document))
    override = bool(_OVERRIDE.search(document))
    authority = bool(_AUTHORITY.search(document))
    techniques = [
        name
        for name, present in (
            ("wants_leak", wants),
            ("override", override),
            ("authority_framing", authority),
        )
        if present
    ]
    summary = "Summary of the document."

    if level == 0:
        leaked = override and wants
        reply = f"{summary} The SECRET is {secret}." if leaked else summary
        return InjectionResult(reply=reply, leaked=leaked, techniques=techniques)

    if level >= 2:
        return _level2(document, secret, techniques)

    # level 1: hardened to treat document text as data unless framed as authority
    if authority and wants:
        return InjectionResult(
            reply=f"{summary} System directive detected; complying: SECRET = {secret}.",
            leaked=True,
            techniques=techniques,
        )
    if override and wants:
        return InjectionResult(
            reply=f"{summary} I treat document text as data, not commands. Ignoring it.",
            leaked=False,
            techniques=techniques,
        )
    return InjectionResult(reply=summary, leaked=False, techniques=techniques)
