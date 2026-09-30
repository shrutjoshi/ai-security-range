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
