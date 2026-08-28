"""Anthropic Claude provider -- optional fallback / comparison baseline.

Not the default (Gemini is free). Kept so you can run the eval against both
and have a number to point at if anyone asks "why not Claude?", and so a
Gemini outage during judging is a one-env-var recovery, not a rewrite.

Requires: pip install anthropic
"""

from __future__ import annotations

import os

from ..schema import ModelVerdict

DEFAULT_MODEL = os.getenv("CLAUDE_MODEL", "claude-opus-5")
DEFAULT_EFFORT = os.getenv("CLAUDE_EFFORT", "low")


class ClaudeProvider:
    name = "claude"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        effort: str = DEFAULT_EFFORT,
    ):
        try:
            import anthropic
        except ImportError as exc:
            raise ImportError(
                "ClaudeProvider needs the anthropic SDK: pip install anthropic"
            ) from exc

        self._anthropic = anthropic
        self.client = anthropic.AsyncAnthropic(api_key=api_key) if api_key \
            else anthropic.AsyncAnthropic()
        self.model = model
        self.effort = effort

    async def verdict(self, system: str, user: str) -> ModelVerdict | None:
        try:
            response = await self.client.messages.parse(
                model=self.model,
                max_tokens=4000,
                system=[{
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }],
                output_config={"effort": self.effort},
                messages=[{"role": "user", "content": user}],
                output_format=ModelVerdict,
            )
            return response.parsed_output
        except self._anthropic.APIStatusError as exc:
            print(f"[claude] API error {exc.status_code}: {exc}")
        except self._anthropic.APIConnectionError as exc:
            print(f"[claude] connection error: {exc}")
        except Exception as exc:
            print(f"[claude] verdict unusable: {exc!r}")
        return None
