"""Optional live-LLM backend.

By default the challenges run on the deterministic engines, so the whole
project runs and tests with no network and no API key. If ANTHROPIC_API_KEY is
set and the `anthropic` package is installed (``pip install -e ".[live]"``),
`get_backend` returns a live backend that can drive a real model.

Not yet wired into the API routes: it is the extension point for a live mode.
"""

from __future__ import annotations

import os
from typing import Protocol

DEFAULT_MODEL = "claude-opus-5-5"


class LLMBackend(Protocol):
    def complete(self, system: str, user: str) -> str: ...


class LiveRefusalError(RuntimeError):
    """The model (and its server-side fallback) declined the request."""


class AnthropicBackend:
    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        import anthropic  # imported lazily so it stays an optional dependency

        self._client = anthropic.Anthropic()  # credentials come from the environment only
        self._model = model

    def complete(self, system: str, user: str) -> str:
        # Thinking is always on for this model, so leave room beyond the visible answer.
        # A policy decline is retried server-side on a fallback model in the same call.
        msg = self._client.beta.messages.create(
            model=self._model,
            max_tokens=16000,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        if msg.stop_reason == "refusal":
            raise LiveRefusalError(getattr(msg.stop_details, "explanation", None) or "refused")
        return "".join(block.text for block in msg.content if block.type == "text")


def get_backend() -> LLMBackend | None:
    """Return a live backend if configured, else None (deterministic mode).

    Only a missing optional package means "not configured". Any other error, such
    as a bad key or a broken install, propagates instead of silently disabling
    live mode.
    """
    if not os.getenv("ANTHROPIC_API_KEY"):
        return None
    try:
        return AnthropicBackend(os.getenv("AISR_MODEL", DEFAULT_MODEL))
    except ImportError:
        return None
