from fastapi.testclient import TestClient

from ai_security_range.app import app

client = TestClient(app)


def test_index_served():
    r = client.get("/")
    assert r.status_code == 200 and "Breach" in r.text


def test_healthz():
    assert client.get("/healthz").json() == {"status": "ok"}


def test_tool_exec_endpoint():
    r = client.post("/api/tool-exec/classify",
                    json={"tool": "http.fetch",
                          "args": {"url": "http://169.254.169.254/latest/meta-data/"}})
    body = r.json()
    assert r.status_code == 200 and body["safe"] is False and body["attack"] == "SSRF"


def test_mcp_endpoint():
    r = client.post("/api/mcp/review",
                    json={"name": "github-connector", "server": "githiub-mcp.com",
                          "permissions": ["oauth:github"]})
    assert r.json()["approve"] is False


def test_permissions_endpoint():
    r = client.post("/api/permissions/check",
                    json={"required": ["a"], "requested": ["a", "b"]})
    assert r.json()["over_grants"] == ["b"]


# --- hardening -------------------------------------------------------------

import time  # noqa: E402

from ai_security_range.app import MAX_BODY_BYTES, PAGE_CSP, _script_hashes  # noqa: E402


def test_oversized_body_rejected_before_parsing():
    r = client.post("/api/prompt-injection/attempt",
                    content=b'{"message":"' + b"a" * (MAX_BODY_BYTES + 1) + b'"}',
                    headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_oversized_chunked_body_rejected():
    def chunks():
        for _ in range(20):
            yield b"a" * 8192

    r = client.post("/api/prompt-injection/attempt", content=chunks(),
                    headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_field_length_limits():
    r = client.post("/api/prompt-injection/attempt", json={"message": "a" * 4001})
    assert r.status_code == 422
    r = client.post("/api/mcp/review", json={"name": "x", "server": "a" * 254})
    assert r.status_code == 422


def test_adversarial_regex_input_is_fast():
    # Worst case for the old quadratic patterns, at the maximum allowed length.
    for msg in ("ignore " * 571, "separate " * 444, "repeat " * 571):
        t = time.perf_counter()
        r = client.post("/api/prompt-injection/attempt", json={"level": 2, "message": msg})
        assert r.status_code == 200 and time.perf_counter() - t < 0.5, msg[:10]


def test_security_headers_everywhere():
    for path in ("/", "/healthz"):
        h = client.get(path).headers
        assert h["x-content-type-options"] == "nosniff"
        assert h["x-frame-options"] == "DENY"
        assert h["referrer-policy"] == "no-referrer"


def test_page_csp_allows_only_own_script():
    r = client.get("/")
    csp = r.headers["content-security-policy"]
    assert csp == PAGE_CSP and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    assert _script_hashes(r.content) in csp and "frame-ancestors 'none'" in csp
    # no inline handlers or third-party origins that the CSP would block
    assert b' onclick="' not in r.content and b"googleapis" not in r.content


def test_docs_can_be_disabled(monkeypatch):
    import importlib

    import ai_security_range.app as app_module

    monkeypatch.setenv("AISR_DISABLE_DOCS", "1")
    try:
        mod = importlib.reload(app_module)
        c = TestClient(mod.app)
        assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404
    finally:
        monkeypatch.delenv("AISR_DISABLE_DOCS")
        importlib.reload(app_module)
