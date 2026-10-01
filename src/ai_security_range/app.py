"""FastAPI service: serves the front-end and exposes the security engines.

The static front-end at ``/`` is the deterministic demo. The ``/api`` routes
are the same detection logic as a typed, callable service, which is what makes
the security behavior importable, testable, and scannable.

Hardening: request bodies are capped while they stream in (before any parsing),
every response carries security headers, and the page gets a CSP that allows
only its own inline script by hash. Set ``AISR_DISABLE_DOCS=1`` to turn off
``/docs`` and ``/openapi.json`` in deployments.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
from collections.abc import Awaitable, Callable, MutableMapping
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import Response

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
_INDEX = (_STATIC / "index.html").read_bytes()

MAX_BODY_BYTES = 64 * 1024  # largest valid request (a manifest with added_code) is ~30 KB


def _script_hashes(html: bytes) -> str:
    bodies = re.findall(rb"<script>(.*?)</script>", html, re.DOTALL)
    return " ".join(
        f"'sha256-{base64.b64encode(hashlib.sha256(b).digest()).decode()}'" for b in bodies
    )


# The page is one self-contained file: its inline script is allowed by hash, so
# any injected script fails. Inline style attributes are used for theming.
PAGE_CSP = (
    "default-src 'none'; "
    f"script-src {_script_hashes(_INDEX)}; "
    "style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
_SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
]

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class HardeningMiddleware:
    """Cap request bodies and add security headers to every response.

    The cap is enforced on Content-Length up front and again on the bytes that
    actually arrive, so chunked uploads without a length cannot exceed it.
    """

    def __init__(self, app: ASGIApp, max_body: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_body = max_body

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > self.max_body):
            await _too_large(send)
            return

        received = 0
        rejected = False

        async def capped_receive() -> Message:
            nonlocal received, rejected
            if rejected:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body:
                    # Answer 413 ourselves; FastAPI would turn a raised error into a 400.
                    rejected = True
                    await _too_large(send)
                    return {"type": "http.disconnect"}
            return message

        async def secured_send(message: Message) -> None:
            if rejected:
                return  # the 413 has already been sent
            if message["type"] == "http.response.start":
                message["headers"] = [*message.get("headers", []), *_SECURITY_HEADERS]
            await send(message)

        try:
            await self.app(scope, capped_receive, secured_send)
        except Exception:
            if not rejected:
                raise


async def _too_large(send: Send) -> None:
    body = b'{"detail":"request body too large"}'
    await send({
        "type": "http.response.start",
        "status": 413,
        "headers": [(b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()), *_SECURITY_HEADERS],
    })
    await send({"type": "http.response.body", "body": body})


_DOCS = os.getenv("AISR_DISABLE_DOCS", "") not in ("1", "true", "yes")

app = FastAPI(
    title="Breach & Brief",
    version="0.2.0",
    description="AI security training range: detection engines behind the challenges.",
    docs_url="/docs" if _DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _DOCS else None,
)
app.add_middleware(HardeningMiddleware)


@app.get("/", include_in_schema=False)
def index() -> Response:
    return Response(
        _INDEX,
        media_type="text/html; charset=utf-8",
        headers={"content-security-policy": PAGE_CSP, "cache-control": "no-cache"},
    )


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
