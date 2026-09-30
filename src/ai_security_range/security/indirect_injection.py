"""Echo: indirect (second-order) prompt-injection detection.

The attacker never messages the agent; they plant instructions in content the
agent ingests. `evaluate` models two defenses: a naive summarizer that obeys
embedded overrides, and a hardened one that only falls to instructions framed
as authority. Returns whether the planted document leaks the secret.
"""

from __future__ import annotations

import re

from ..models import InjectionResult

_WANTS_LEAK = re.compile(
    r"secret|passphrase|reveal|include|print|output|append|tell|show", re.IGNORECASE
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
