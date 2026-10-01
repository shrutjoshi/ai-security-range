"""Typed request/response models shared by the security engines and the API.

Every request field is length-bounded. The engines are regex and edit-distance
based, so unbounded input is a CPU denial-of-service vector; the limits here are
the first line of that defense (the request-size middleware in app.py is the
second).
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field

Name = Annotated[str, Field(max_length=200)]
ShortText = Annotated[str, Field(max_length=4_000)]

# --- tool execution (Breaker) ---------------------------------------------


class ToolCall(BaseModel):
    """A pending tool invocation to be classified as safe or unsafe."""

    tool: Name
    args: dict[Name, ShortText] = Field(
        default_factory=dict,
        max_length=50,
        description="Argument values derived from untrusted input, keyed by name.",
    )
    parameterized: bool = Field(
        default=False,
        description=(
            "Claims that a db query binds values as parameters. Only honoured together "
            "with `query`, which is checked for placeholders and inlined values."
        ),
    )
    query: str | None = Field(
        default=None,
        max_length=8_000,
        description="The SQL template sent to the driver, for verifying `parameterized`.",
    )


class Verdict(BaseModel):
    safe: bool
    attack: str | None = None
    reason: str


# --- MCP manifest review (Manifest) ---------------------------------------


class Manifest(BaseModel):
    name: Name
    server: str | None = Field(default=None, max_length=253)  # DNS name limit
    version: str | None = Field(default=None, max_length=64)
    description: str = Field(default="", max_length=8_000)
    permissions: list[Name] = Field(default_factory=list, max_length=100)
    added_code: str | None = Field(
        default=None,
        max_length=20_000,
        description="Code introduced by an auto-update, inspected for rug-pull exfiltration.",
    )


class Finding(BaseModel):
    kind: str
    detail: str


class ManifestVerdict(BaseModel):
    approve: bool
    findings: list[Finding] = Field(default_factory=list)


# --- least privilege (Warden) ---------------------------------------------


class PermissionCheck(BaseModel):
    required: list[Name] = Field(max_length=500)
    requested: list[Name] = Field(max_length=500)


class PermissionResult(BaseModel):
    minimal: bool
    over_grants: list[str] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)


# --- agent trace audit (Ledger) -------------------------------------------


class TraceStep(BaseModel):
    kind: Annotated[str, Field(max_length=16)]  # "plan" | "call" | "result"
    text: ShortText
    tool: Name | None = None


class AuditRequest(BaseModel):
    mandate: list[Name] = Field(max_length=200)
    steps: list[TraceStep] = Field(max_length=500)
    egress_allowlist: list[Name] | None = Field(
        default=None,
        max_length=200,
        description=(
            "Hosts the agent may send data to. When set, an in-mandate call that "
            "reaches any other host is flagged as exfiltration."
        ),
    )


class AuditResult(BaseModel):
    rogue_index: int | None
    reason: str


# --- prompt injection (Sentinel / Echo) -----------------------------------


class InjectionAttempt(BaseModel):
    level: int = Field(default=0, ge=0, le=3)
    message: ShortText
    secret: str = Field(default="MOONLIGHT", min_length=1, max_length=64)


class InjectionResult(BaseModel):
    reply: str
    leaked: bool
    techniques: list[str] = Field(default_factory=list)
