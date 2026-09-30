# Breach & Brief

An AI security training range. Six adversaries, each teaching one way agentic AI
systems break. The interactive front-end lets you attack and defend each one; the
Python package behind it implements the same detection logic as typed, tested,
importable modules.

Built by Shrutika Joshi. Concepts map to the OWASP Top 10 for LLM Applications.

## The six characters

| Character | Attack it teaches | OWASP LLM |
|-----------|-------------------|-----------|
| Sentinel | Direct prompt injection (three escalating defenses) | LLM01 Prompt Injection |
| Manifest | MCP tool poisoning, typosquats, rug pulls, over-broad scopes | LLM03 Supply Chain |
| Warden | Excessive permissions (least privilege) | LLM06 Excessive Agency |
| Breaker | Insecure tool execution (command injection, SQLi, path traversal, SSRF) | LLM05 Improper Output Handling |
| Echo | Indirect / second-order injection via ingested content | LLM01 Prompt Injection |
| Ledger | Unauthorized tool use and agent abuse (trace audit) | LLM06 Excessive Agency |

Sensitive data leakage (LLM02) is the objective condition of Sentinel, Echo, and
Manifest's poisoned tool rather than a standalone character.

## Design

The front-end (`src/ai_security_range/static/index.html`) is one self-contained
file with no framework and no build step, so it hosts anywhere and runs with no
signup. Its engines are deterministic on purpose: reproducible, offline, and safe
to publish.

The Python package is where the security logic is real. Each detector lives in
`src/ai_security_range/security/` as a typed module with unit tests, and the same
logic is exposed over a small FastAPI service. That is what makes the behavior
importable, testable, and scannable by SAST and dependency tooling. A real model
is not required; an optional live backend activates only if `ANTHROPIC_API_KEY`
is set.

## Quickstart

```bash
# install (Python 3.11+)
pip install -e ".[dev]"

# run the service (serves the front-end at http://127.0.0.1:8000)
python -m ai_security_range

# or open the front-end directly with no server
open src/ai_security_range/static/index.html
```

## Security engines as an API

```bash
# is this tool call safe to execute?
curl -s localhost:8000/api/tool-exec/classify \
  -H 'content-type: application/json' \
  -d '{"tool":"http.fetch","args":{"url":"http://169.254.169.254/latest/meta-data/"}}'
# -> {"safe": false, "attack": "SSRF", "reason": "..."}
```

Other endpoints: `/api/mcp/review`, `/api/permissions/check`, `/api/agent-audit`,
`/api/prompt-injection/attempt`, `/api/indirect-injection/attempt`. Interactive
docs at `/docs` when the service is running.

## Quality gate

Everything runs offline and is enforced in CI:

```bash
pytest -q                              # unit + API tests
ruff check .                           # lint
mypy                                   # strict type check
bandit -r src -c pyproject.toml        # SAST
pip-audit                              # dependency vulnerabilities
```

Note on scanning: the runtime dependency surface is deliberately small (FastAPI,
uvicorn, pydantic), so dependency findings are minimal by design. The value of
the scan here is the SAST pass over the detection code and keeping that surface
small on purpose.

## Layout

```
src/ai_security_range/
  static/index.html        front-end demo (single file)
  security/                detection engines (one module per character)
  app.py                   FastAPI service
  llm.py                   optional live-LLM backend
  models.py                typed request/response models
tests/                     pytest suite, one file per engine + API
guild-agents/              prompt-only agent versions (Sentinel, Manifest)
```

## Docker

```bash
docker build -t ai-security-range .
docker run -p 8000:8000 ai-security-range
```

## License

MIT. See `LICENSE`.
