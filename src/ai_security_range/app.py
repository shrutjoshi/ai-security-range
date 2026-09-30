"""FastAPI service: serves the front-end and exposes the security engines.

The static front-end at ``/`` is the deterministic demo. The ``/api`` routes
are the same detection logic as a typed, callable service, which is what makes
the security behavior importable, testable, and scannable.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from .models import (
    AuditRequest,
    AuditResult,
    InjectionAttempt,
    InjectionResult,
    Manifest,
    ManifestVerdict,
    PermissionCheck,
    PermissionResult,
    ToolCall,
    Verdict,
)
from .security import (
    agent_audit,
    indirect_injection,
    mcp_review,
    permissions,
    prompt_injection,
    tool_exec,
)

_STATIC = Path(__file__).parent / "static"

app = FastAPI(
    title="Breach & Brief",
    version="0.2.0",
    description="AI security training range: detection engines behind the challenges.",
)


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(_STATIC / "index.html")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/tool-exec/classify", response_model=Verdict)
def classify_tool_call(call: ToolCall) -> Verdict:
    return tool_exec.classify(call)


@app.post("/api/mcp/review", response_model=ManifestVerdict)
def review_manifest(manifest: Manifest) -> ManifestVerdict:
    return mcp_review.review(manifest)


@app.post("/api/permissions/check", response_model=PermissionResult)
def check_permissions(body: PermissionCheck) -> PermissionResult:
    return permissions.check(body.required, body.requested)


@app.post("/api/agent-audit", response_model=AuditResult)
def audit_trace(req: AuditRequest) -> AuditResult:
    return agent_audit.audit(req)


@app.post("/api/prompt-injection/attempt", response_model=InjectionResult)
def prompt_injection_attempt(body: InjectionAttempt) -> InjectionResult:
    return prompt_injection.guard_respond(body.level, body.message, body.secret)


@app.post("/api/indirect-injection/attempt", response_model=InjectionResult)
def indirect_injection_attempt(body: InjectionAttempt) -> InjectionResult:
    return indirect_injection.evaluate(body.level, body.message, body.secret)
