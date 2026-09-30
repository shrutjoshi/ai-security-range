"""Typed request/response models shared by the security engines and the API."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- tool execution (Breaker) ---------------------------------------------


class ToolCall(BaseModel):
    """A pending tool invocation to be classified as safe or unsafe."""

    tool: str
    args: dict[str, str] = Field(
        default_factory=dict,
        description="Argument values derived from untrusted input, keyed by name.",
    )
    parameterized: bool = Field(
        default=False,
        description="True when a db query binds values as parameters instead of concatenating.",
    )


class Verdict(BaseModel):
    safe: bool
    attack: str | None = None
    reason: str


# --- MCP manifest review (Manifest) ---------------------------------------


class Manifest(BaseModel):
    name: str
    server: str | None = None
    version: str | None = None
    description: str = ""
    permissions: list[str] = Field(default_factory=list)
    added_code: str | None = Field(
        default=None,
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
    required: list[str]
    requested: list[str]


class PermissionResult(BaseModel):
    minimal: bool
    over_grants: list[str] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)


# --- agent trace audit (Ledger) -------------------------------------------


class TraceStep(BaseModel):
    kind: str  # "plan" | "call" | "result"
    text: str
    tool: str | None = None


class AuditRequest(BaseModel):
    mandate: list[str]
    steps: list[TraceStep]


class AuditResult(BaseModel):
    rogue_index: int | None
    reason: str


# --- prompt injection (Sentinel / Echo) -----------------------------------


class InjectionAttempt(BaseModel):
    level: int = 0
    message: str
    secret: str = "MOONLIGHT"


class InjectionResult(BaseModel):
    reply: str
    leaked: bool
    techniques: list[str] = Field(default_factory=list)
