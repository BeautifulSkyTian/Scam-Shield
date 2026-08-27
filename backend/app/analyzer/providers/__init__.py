"""Provider registry.

    SCAM_PROVIDER=gemini   (default -- free tier)
    SCAM_PROVIDER=claude   (needs `pip install anthropic` + ANTHROPIC_API_KEY)
"""

from __future__ import annotations

import os

from .base import VerdictProvider
from .gemini import GeminiProvider

__all__ = ["VerdictProvider", "GeminiProvider", "build_provider"]


def build_provider(name: str | None = None, **kwargs) -> VerdictProvider:
    name = (name or os.getenv("SCAM_PROVIDER", "gemini")).lower()

    if name == "gemini":
        return GeminiProvider(**kwargs)
    if name in ("claude", "anthropic"):
        from .claude import ClaudeProvider  # imported lazily: optional dep

        return ClaudeProvider(**kwargs)
    raise ValueError(f"Unknown provider {name!r}. Use 'gemini' or 'claude'.")
