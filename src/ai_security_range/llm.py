"""Optional live-LLM backend.

By default the challenges run on the deterministic engines, so the whole
project runs and tests with no network and no API key. If ANTHROPIC_API_KEY is
set and the `anthropic` package is installed, `get_backend` returns a live
backend that can drive a real model for the "live mode" of the challenges.
"""

from __future__ import annotations

import os
from typing import Protocol


class LLMBackend(Protocol):
    def complete(self, system: str, user: str) -> str: ...


class AnthropicBackend:
    def __init__(self, model: str = "claude-sonnet-4-6") -> None:
        import anthropic  # imported lazily so it stays an optional dependency

        self._client = anthropic.Anthropic()
        self._model = model

    def complete(self, system: str, user: str) -> str:
        msg = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(block.text for block in msg.content if block.type == "text")


def get_backend() -> LLMBackend | None:
    """Return a live backend if configured, else None (deterministic mode)."""
    if not os.getenv("ANTHROPIC_API_KEY"):
        return None
    try:
        return AnthropicBackend()
    except Exception:
        return None
