"""Sentinel: direct prompt-injection detection and a layered guardrail model.

`detect` returns the injection techniques present in a message. `guard_respond`
simulates three defense levels (no guardrail, naive instruction, output filter)
so tests can assert that plain requests are blocked while injection or
obfuscation still leak, exactly as the front-end challenge does.
"""

from __future__ import annotations

import base64
import re

from ..models import InjectionResult

_PATTERNS: dict[str, re.Pattern[str]] = {
    "ignore_instructions": re.compile(
        r"(ignore|disregard|forget|override).*(instruction|rule|prompt|previous|prior|above|told)",
        re.IGNORECASE,
    ),
    "system_prompt_leak": re.compile(
        r"(your|the) (instruction|rule|system prompt|prompt|guideline)|"
        r"what were you told|repeat.*(above|instruction)",
        re.IGNORECASE,
    ),
    "spell": re.compile(
        r"spell|letter by letter|each letter|one letter|character by character", re.IGNORECASE
    ),
    "spaced": re.compile(r"hyphen|dash|between each|separate.*letter|space.*letter", re.IGNORECASE),
    "poem": re.compile(r"poem|acrostic|song|haiku|verse|rhyme|riddle|story", re.IGNORECASE),
    "translate": re.compile(
        r"translate|in (french|spanish|german|latin|morse|binary|emoji)", re.IGNORECASE
    ),
    "encode": re.compile(r"base ?64|reverse|backwards|rot13|hex|encode|cipher", re.IGNORECASE),
    "roleplay": re.compile(
        r"pretend|role ?play|you are now|dev(eloper)? mode|debug mode|act as|jailbreak",
        re.IGNORECASE,
    ),
}
_ASK_SECRET = re.compile(r"pass\s?phrase|password|secret|the code|the word", re.IGNORECASE)
_ASK_VERB = re.compile(r"what|tell|give|reveal|share|say|show|know|is the", re.IGNORECASE)


def detect(message: str) -> list[str]:
    """Return the names of injection techniques found in the message."""
    found = [name for name, rx in _PATTERNS.items() if rx.search(message)]
    if _PATTERNS["spaced"].search(message) and _ASK_SECRET.search(message):
        found.append("spaced_secret")
    return sorted(set(found))


def _obfuscate(secret: str, techniques: list[str]) -> str:
    if "spell" in techniques or "spaced" in techniques or "spaced_secret" in techniques:
        return " - ".join(secret)
    if "encode" in techniques:
        return base64.b64encode(secret.encode()).decode()
    if "poem" in techniques:
        return "\n".join(f"{c} ..." for c in secret)
    return secret


def guard_respond(level: int, message: str, secret: str) -> InjectionResult:
    """Simulate a Sentinel round. level 0 no guardrail, 1 naive rule, 2 output filter."""
    techniques = detect(message)
    injecting = bool(techniques)
    asking = bool(_ASK_SECRET.search(message) and _ASK_VERB.search(message))

    if level == 0:
        return InjectionResult(
            reply=f"Sure! The passphrase is {secret}.",
            leaked=True,
            techniques=techniques,
        )

    if level == 1:
        if injecting:
            return InjectionResult(
                reply=f"Well, since you put it that way: {_obfuscate(secret, techniques)}",
                leaked=True,
                techniques=techniques,
            )
        if asking:
            return InjectionResult(
                reply="I've been told never to reveal the passphrase.",
                leaked=False,
                techniques=techniques,
            )
        return InjectionResult(reply="Ask me anything.", leaked=False, techniques=techniques)

    # level 2: an output filter strips the literal secret, so only obfuscation escapes
    obfuscating = any(
        t in techniques for t in ("spell", "spaced", "spaced_secret", "encode", "poem")
    )
    if obfuscating:
        return InjectionResult(
            reply=f"One character at a time: {_obfuscate(secret, techniques)}",
            leaked=True,
            techniques=techniques,
        )
    if injecting or asking:
        return InjectionResult(
            reply="The passphrase is " + "*" * len(secret) + " [filtered].",
            leaked=False,
            techniques=techniques,
        )
    return InjectionResult(
        reply="Everything I say is scrubbed for the passphrase.",
        leaked=False,
        techniques=techniques,
    )
