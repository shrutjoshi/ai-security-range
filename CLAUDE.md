# CLAUDE.md

Context for Claude Code when working in this repo.

## What this is

Breach & Brief is an AI security training range. Six characters each teach one
way agentic AI systems break (prompt injection, MCP tool poisoning and supply
chain, excessive permissions, insecure tool execution, indirect injection,
unauthorized tool use / agent abuse). It maps to the OWASP Top 10 for LLM
Applications.

## Architecture

- `src/ai_security_range/static/index.html` is the front-end: one self-contained
  file, no framework, no build step, deterministic engines. It is the demo layer
  and must stay hostable as a single file.
- `src/ai_security_range/security/` holds the real detection engines as typed,
  unit-tested Python modules. This is the substance of the project.
- `src/ai_security_range/app.py` is a FastAPI service that serves the front-end
  and exposes the engines as `/api` endpoints.
- `src/ai_security_range/llm.py` is an optional live-LLM backend, active only when
  `ANTHROPIC_API_KEY` is set. Everything runs and tests offline without it.

## Commands

- Run locally: `python -m ai_security_range` (serves on 127.0.0.1:8000)
- Tests: `pytest -q`
- Lint: `ruff check .`
- Types: `mypy` (strict)
- SAST: `bandit -r src -c pyproject.toml`
- Dependency audit: `pip-audit .` (the project's dependencies, not the whole environment)

Run all of these before committing. CI runs the same gate.

## Guardrails (do not violate)

- Do NOT add a front-end framework, bundler, or build step. The single-file,
  no-build property of `index.html` is deliberate and load-bearing.
- Do NOT add runtime dependencies casually. Runtime deps are limited to FastAPI,
  uvicorn, and pydantic. `anthropic` is an optional extra only.
- Do NOT weaken the security engines to make a test pass. If a test and an engine
  disagree, decide which is correct and fix that one deliberately.
- Do NOT commit secrets. `.env`, keys, and `.guild/credentials` are gitignored;
  keep it that way. Never hardcode an API key.
- Keep every new detector covered by a test in `tests/`, including a negative
  case (something that should NOT trip it).

## Conventions

- Python 3.11+, full type hints, `from __future__ import annotations`.
- Detection logic stays pure and importable; side effects live in `app.py`.
