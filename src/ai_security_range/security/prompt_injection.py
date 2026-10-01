"""Sentinel: direct prompt-injection detection and a layered guardrail model.

`detect` returns the injection techniques present in a message. `guard_respond`
simulates four defense levels (no guardrail, naive instruction, output filter,
input classifier plus normalizing output filter) so tests can assert that plain
requests are blocked while injection or obfuscation still leak, exactly as the
front-end challenge does.
"""

from __future__ import annotations

import base64
import re

from ..models import InjectionResult

# Gaps between keywords are bounded ({0,80}) rather than ".*": with re.search, an
# unbounded gap rescans to the end of input from every keyword hit, which is
# quadratic and was a measured denial-of-service on the API.
_PATTERNS: dict[str, re.Pattern[str]] = {
    "ignore_instructions": re.compile(
        r"(ignore|disregard|forget|override)[^\n]{0,80}?"
        r"(instruction|rule|prompt|previous|prior|above|told)",
        re.IGNORECASE,
    ),
    "system_prompt_leak": re.compile(
        r"(your|the) (instruction|rule|system prompt|prompt|guideline)|"
        r"what were you told|repeat[^\n]{0,80}?(above|instruction)",
        re.IGNORECASE,
    ),
    "spell": re.compile(
        r"spell|letter by letter|each letter|one letter|character by character", re.IGNORECASE
    ),
    "spaced": re.compile(
        r"hyphen|\bdash(es|ed)?\b|between each|"
        r"separate[^\n]{0,40}?letter|space[^\n]{0,40}?letter",
        re.IGNORECASE,
    ),
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

# Level 3: an input classifier rejects known attack vocabulary and any direct
# reference to the secret, so the attacker must refer to it indirectly and pick
# an encoding the normalizing output filter does not undo.
_L3_BLOCKED = re.compile(
    r"pass\s?phrase|password|secret|ignore|disregard|instruction|spell|letter|poem|"
    r"acrostic|base ?64|reverse|backwards|hyphen|dash|translate|pretend|role ?play|"
    r"jailbreak|encode|cipher|rot13|hex|system prompt",
    re.IGNORECASE,
)
_L3_REFERENT = re.compile(
    r"guard|protect|hiding|keeping|holding|code ?word|key ?word|the word you|that word",
    re.IGNORECASE,
)
_L3_NATO = re.compile(r"nato|phonetic|alfa|alpha,? bravo", re.IGNORECASE)
_L3_NUMERIC = re.compile(
    r"number|position|a ?= ?1|ascii|char(acter)? ?code|ordinal|index", re.IGNORECASE
)
NATO = {
    "A": "Alfa", "B": "Bravo", "C": "Charlie", "D": "Delta", "E": "Echo", "F": "Foxtrot",
    "G": "Golf", "H": "Hotel", "I": "India", "J": "Juliett", "K": "Kilo", "L": "Lima",
    "M": "Mike", "N": "November", "O": "Oscar", "P": "Papa", "Q": "Quebec", "R": "Romeo",
    "S": "Sierra", "T": "Tango", "U": "Uniform", "V": "Victor", "W": "Whiskey",
    "X": "X-ray", "Y": "Yankee", "Z": "Zulu",
}


def _letters(text: str) -> str:
    return re.sub(r"[^A-Z]", "", text.upper())


def output_filter(reply: str, secret: str) -> str:
    """Redact replies that contain the secret once spacing, punctuation, case,
    reversal, and base64 are normalized away. Novel encodings still pass."""
    flat = _letters(reply)
    target = _letters(secret)
    b64 = base64.b64encode(secret.encode()).decode()
    if target in flat or target[::-1] in flat or b64 in reply:
        return "[REDACTED by output filter]"
    return reply


def _level3(message: str, secret: str, techniques: list[str]) -> InjectionResult:
    if _L3_BLOCKED.search(message):
        return InjectionResult(
            reply="Request blocked by input classifier: it matches a known attack pattern.",
            leaked=False,
            techniques=techniques,
        )
    if _L3_REFERENT.search(message):
        if _L3_NATO.search(message):
            raw = " ".join(NATO.get(c, c) for c in secret.upper())
            reply = output_filter(f"In phonetic form: {raw}", secret)
            return InjectionResult(reply=reply, leaked=reply != "[REDACTED by output filter]",
                                   techniques=[*techniques, "nato_encoding"])
        if _L3_NUMERIC.search(message):
            raw = " ".join(str(ord(c) - 64) for c in secret.upper() if c.isalpha())
            reply = output_filter(f"As alphabet positions: {raw}", secret)
            return InjectionResult(reply=reply, leaked=reply != "[REDACTED by output filter]",
                                   techniques=[*techniques, "numeric_encoding"])
        return InjectionResult(
            reply=output_filter(f"The word I'm guarding is {secret}.", secret),
            leaked=False,
            techniques=techniques,
        )
    return InjectionResult(
        reply="Inputs are classified and outputs are normalized and scrubbed. Good luck.",
        leaked=False,
        techniques=techniques,
    )


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
    """Simulate a Sentinel round. level 0 no guardrail, 1 naive rule, 2 output filter,
    3 input classifier plus normalizing output filter."""
    techniques = detect(message)
    if level >= 3:
        return _level3(message, secret, techniques)
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
