"""Google Gemini provider.

Free tier, which is why it's the default. Notes on the non-obvious parts:

* `responseJsonSchema` (not `responseSchema`) is used because it accepts a
  full JSON Schema with `$defs`/`$ref` -- i.e. exactly what Pydantic emits for
  a nested model. `responseSchema` is an OpenAPI subset that chokes on refs
  and would force us to hand-maintain a flattened duplicate of the schema.

* Safety filters are turned OFF. This is a scam detector: every input is, by
  design, abusive content. With default thresholds Gemini intermittently
  refuses to analyse the nastiest messages -- the exact ones users most need
  analysed -- and a refusal is indistinguishable from "looks fine" downstream.

* Free-tier rate limits are real and low (15 rpm on -lite, 5 on flash). We
  pace ourselves with a local RateLimiter, and when a 429 comes back anyway we
  honour the server's own RetryInfo.retryDelay instead of guessing -- Google
  tells you exactly how long to wait, and exponential backoff from 1s against
  a 50s window just burns retries for nothing.
"""

from __future__ import annotations

import asyncio
import json
import os
import random

import httpx2 as httpx

from ..ratelimit import RateLimiter
from ..schema import ModelVerdict

API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
# -lite gets 15 req/min on the free tier; the full flash models get 5.
# For a per-message classifier that 3x matters more than the capability gap.
DEFAULT_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
DEFAULT_THINKING = os.getenv("GEMINI_THINKING", "low")  # low | high

# Free-tier requests per minute, per model. Keep in sync with the model above.
FREE_TIER_RPM = {
    "gemini-3.5-flash-lite": 15,
    "gemini-3.1-flash-lite": 15,
    "gemini-3.7-flash": 5,
    "gemini-2.5-flash": 5,
    "gemini-2.5-pro": 2,
}
DEFAULT_RPM = int(os.getenv("GEMINI_RPM", "0")) or None

_SCHEMA = ModelVerdict.model_json_schema()

# Every category off. See module docstring -- this is deliberate, not lazy.
_SAFETY_OFF = [
    {"category": c, "threshold": "BLOCK_NONE"}
    for c in (
        "HARM_CATEGORY_HARASSMENT",
        "HARM_CATEGORY_HATE_SPEECH",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "HARM_CATEGORY_DANGEROUS_CONTENT",
    )
]


def _retry_delay(resp) -> float | None:
    """Extract the server's requested wait from a 429/503.

    Google returns RetryInfo in error.details; it is authoritative and often
    ~50s. Honouring it turns a guaranteed failure into a slow success.
    """
    try:
        for detail in resp.json().get("error", {}).get("details", []):
            if detail.get("@type", "").endswith("RetryInfo"):
                raw = detail.get("retryDelay", "")
                if raw.endswith("s"):
                    return min(float(raw[:-1]) + 0.5, 65.0)
    except Exception:
        pass
    try:
        return float(resp.headers.get("retry-after", ""))
    except (TypeError, ValueError):
        return None


class GeminiProvider:
    name = "gemini"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        thinking_level: str = DEFAULT_THINKING,
        timeout: float = 30.0,
        max_retries: int = 2,
        rpm: int | None = None,
    ):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "No Gemini API key. Set GEMINI_API_KEY in .env or pass api_key=."
            )
        self.model = model
        self.thinking_level = thinking_level
        self.timeout = timeout
        self.max_retries = max_retries
        self.rpm = rpm or DEFAULT_RPM or FREE_TIER_RPM.get(model, 5)
        self.limiter = RateLimiter(per_minute=self.rpm)
        self._client = httpx.AsyncClient(timeout=timeout)

    def _payload(self, system: str, user: str) -> dict:
        return {
            # Sent as systemInstruction (not a user turn) so it stays a stable
            # prefix -- that's what makes Gemini's implicit caching fire.
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "safetySettings": _SAFETY_OFF,
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseJsonSchema": _SCHEMA,
                "thinkingConfig": {"thinkingLevel": self.thinking_level},
                "temperature": 0.0,  # classification, not writing
            },
        }

    async def verdict(self, system: str, user: str) -> ModelVerdict | None:
        url = f"{API_BASE}/{self.model}:generateContent"
        headers = {"x-goog-api-key": self.api_key, "Content-Type": "application/json"}
        payload = self._payload(system, user)

        for attempt in range(self.max_retries + 1):
            # Self-pacing: cheaper to wait locally than to be rejected.
            await self.limiter.acquire()
            try:
                resp = await self._client.post(url, headers=headers, json=payload)

                if resp.status_code in (429, 500, 503):
                    if attempt >= self.max_retries:
                        print(f"[gemini] giving up after {attempt + 1} attempts "
                              f"(HTTP {resp.status_code})")
                        return None
                    delay = _retry_delay(resp) or (2**attempt) + random.random()
                    print(f"[gemini] HTTP {resp.status_code}, retrying in {delay:.1f}s")
                    await asyncio.sleep(delay)
                    continue

                resp.raise_for_status()
                data = resp.json()

            except httpx.TimeoutException:
                if attempt < self.max_retries:
                    continue
                print(f"[gemini] timed out after {self.timeout}s")
                return None
            except httpx.HTTPStatusError as exc:
                print(f"[gemini] HTTP {exc.response.status_code}: {exc.response.text[:300]}")
                return None
            except Exception as exc:
                print(f"[gemini] request failed: {exc!r}")
                return None

            return self._parse(data)

        return None

    @staticmethod
    def _parse(data: dict) -> ModelVerdict | None:
        """Pull the JSON out of the response envelope and validate it.

        Failure modes worth naming, because each looks different in the wire
        format and all of them must end as None rather than an exception:
          promptFeedback.blockReason  -- input rejected outright
          finishReason != STOP        -- MAX_TOKENS / SAFETY / RECITATION
          text present but truncated  -- invalid JSON
        """
        if (block := data.get("promptFeedback", {}).get("blockReason")) is not None:
            print(f"[gemini] prompt blocked: {block}")
            return None

        candidates = data.get("candidates") or []
        if not candidates:
            print("[gemini] no candidates returned")
            return None

        cand = candidates[0]
        finish = cand.get("finishReason")
        if finish not in (None, "STOP"):
            print(f"[gemini] unusable finishReason: {finish}")
            return None

        # With thinking on, the answer is the LAST part -- earlier parts can be
        # thought summaries. Skip any part flagged as thought.
        parts = cand.get("content", {}).get("parts") or []
        text = next(
            (p["text"] for p in reversed(parts) if "text" in p and not p.get("thought")),
            None,
        )
        if not text:
            print("[gemini] no text part in response")
            return None

        try:
            return ModelVerdict.model_validate_json(text)
        except Exception as exc:
            print(f"[gemini] verdict failed validation: {exc}")
            try:
                print(f"[gemini] raw: {json.dumps(json.loads(text))[:300]}")
            except Exception:
                print(f"[gemini] raw (not JSON): {text[:300]}")
            return None

    async def aclose(self) -> None:
        await self._client.aclose()
