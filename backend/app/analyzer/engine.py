"""Orchestration: request in, AnalysisResult out.

    AnalyzeRequest
        |
        +--> check_links()      deterministic + Google Safe Browsing
        +--> provider.verdict() Gemini (default) or Claude -- signals + tone
        |
        v
      score_signals()  ->  band  ->  AnalysisResult

The engine knows nothing about any LLM SDK. It talks to `VerdictProvider`,
which is allowed to fail but never to raise.
"""

from __future__ import annotations

import hashlib
import time
from collections import OrderedDict

from .categories import CATEGORY_LABELS, LINK_OWNED_SIGNALS, ScamCategory, Severity, Signal
from .links import LinkFinding, check_links
from .prefilter import needs_model
from .prompts import SYSTEM_PROMPT, build_user_content
from .providers import VerdictProvider, build_provider
from .schema import AnalysisResult, AnalyzeRequest, LinkVerdict, ModelVerdict
from .scoring import (
    RECOMMENDED_ACTION,
    apply_category_floor,
    band_for,
    headline_for,
    score_signals,
)


class _LRU(OrderedDict):
    """Tiny result cache. The same message gets re-sent constantly -- a mail
    client re-renders the thread on every scroll -- and on a free tier those
    duplicate calls are the difference between working and rate-limited."""

    def __init__(self, maxsize: int = 512):
        super().__init__()
        self.maxsize = maxsize

    def put(self, key: str, value: AnalysisResult) -> None:
        self[key] = value
        self.move_to_end(key)
        while len(self) > self.maxsize:
            self.popitem(last=False)

    def get_(self, key: str) -> AnalysisResult | None:
        if key not in self:
            return None
        self.move_to_end(key)
        return self[key]


def _cache_key(req: AnalyzeRequest) -> str:
    payload = "\x00".join(
        [req.text, req.sender or "", req.subject or "", req.source or ""]
        + sorted(f"{l.href}|{l.text or ''}" for l in req.links)
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class ScamAnalyzer:
    """Stateless per-request; construct once and share.

    Person 3: build one of these at FastAPI startup and hold it on app.state.
    Constructing it per request throws away the cache and the connection pool,
    and on a free tier that will get you throttled.
    """

    def __init__(
        self,
        provider: VerdictProvider | None = None,
        safe_browsing_key: str | None = None,
        cache_size: int = 512,
        use_prefilter: bool = True,
    ):
        self.provider = provider or build_provider()
        self.safe_browsing_key = safe_browsing_key
        self.use_prefilter = use_prefilter
        self._cache = _LRU(cache_size)

    async def analyze(self, req: AnalyzeRequest) -> AnalysisResult:
        started = time.perf_counter()

        key = _cache_key(req)
        if (hit := self._cache.get_(key)) is not None:
            return hit.model_copy(update={"cached": True})

        # Link check first: its findings are cheap, deterministic, and give the
        # model real evidence to reason about when judging intent.
        link_verdicts, link_findings = await check_links(
            req.text, req.links, self.safe_browsing_key
        )
        link_notes = [
            f"{v.url} -> {v.verdict}" + (f" ({'; '.join(v.reasons)})" if v.reasons else "")
            for v in link_verdicts
        ]

        # Spend an API call only if the message could plausibly be a scam.
        # On a 15-rpm free tier this is the difference between an extension
        # that scans a whole inbox and one that rate-limits on page load.
        analyzed_by = "model"
        verdict = None
        if self.use_prefilter and not link_findings:
            should_call, why = needs_model(req.text, req.links)
            if not should_call:
                analyzed_by = "prefilter"

        if analyzed_by == "model":
            verdict = await self.provider.verdict(
                SYSTEM_PROMPT,
                build_user_content(req.text, req.sender, req.subject, req.source, link_notes),
            )
            if verdict is None:
                analyzed_by = "link_check_only"

        result = self._assemble(verdict, link_verdicts, link_findings)
        result.analyzed_by = analyzed_by
        result.degraded = analyzed_by == "link_check_only"
        result.analysis_ms = round((time.perf_counter() - started) * 1000)

        self._cache.put(key, result)
        return result

    def _assemble(
        self,
        verdict: ModelVerdict | None,
        link_verdicts: list[LinkVerdict],
        link_findings: list[LinkFinding],
    ) -> AnalysisResult:
        scored: list[tuple[Signal, Severity, str, str, str]] = []

        for f in link_findings:
            scored.append((f.signal, f.severity, f.evidence, f.explanation, "link_check"))

        if verdict is not None:
            for s in verdict.signals:
                # Defensive: the model was told not to emit link signals. If it
                # does anyway, drop it -- link_check is the authority and we
                # would otherwise double-count the same evidence.
                if s.signal in LINK_OWNED_SIGNALS:
                    continue
                scored.append((s.signal, s.severity, s.evidence, s.explanation, "model"))

        score, factors = score_signals(scored)

        category = verdict.category if verdict else ScamCategory.BENIGN
        if verdict is None and link_findings:  # noqa: SIM102
            # Degraded: bad links, but no model read on intent.
            category = ScamCategory.PHISHING

        score = apply_category_floor(score, category, bool(factors))
        band, action = band_for(score)

        return AnalysisResult(
            risk_score=score,
            risk_band=band,
            action=action,
            category=category,
            category_label=CATEGORY_LABELS.get(category, "Unknown"),
            headline=headline_for(score, category, factors),
            likely_goal=verdict.likely_goal if verdict else None,
            confidence=verdict.confidence if verdict else "low",
            factors=factors,
            links=link_verdicts,
            tone=verdict.tone if verdict else None,
            recommended_action=RECOMMENDED_ACTION[action],
            # Set correctly by analyze(); a prefiltered result is not degraded.
            degraded=verdict is None,
        )
