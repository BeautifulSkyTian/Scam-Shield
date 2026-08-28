"""Scam analysis service.

Public surface is unchanged: `analyze_scam(request) -> AnalyzeResponse` and
`AIServiceError`. `main.py` needs no edits.

What changed is everything behind it. Previously this file sent one prompt to
Gemini and trusted whatever risk score came back. Now:

  * the model extracts typed *signals* with verbatim evidence quotes, and a
    deterministic scorer turns those into the number -- so the same message
    always scores the same, which a model-authored score does not
  * URLs go to a reputation checker (heuristics + Google Safe Browsing), never
    to the model, which cannot actually check a domain and will guess
  * obviously-benign messages skip the API entirely, and a rate limiter keeps
    us inside the free tier

See app/analyzer/README.md for the design and the measured eval results.
"""

from __future__ import annotations

import os

from app.analyzer import AnalyzeRequest as AnalyzerRequest
from app.analyzer import AnalysisResult, AnalyzerRuntime
from app.analyzer import LinkInput as AnalyzerLink
from app.core.config import GEMINI_API_KEY
from app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    LinkReport,
    RiskReason,
    ToneReport,
)

ANALYZE_TIMEOUT_S = float(os.getenv("ANALYZE_TIMEOUT_S", "30"))


class AIServiceError(Exception):
    pass


# One runtime for the process: one event loop, one HTTP pool, one rate
# limiter, one result cache. Building this per request would silently disable
# the rate limiting and get us throttled.
_runtime = AnalyzerRuntime(
    default_timeout=ANALYZE_TIMEOUT_S,
    safe_browsing_key=os.getenv("SAFE_BROWSING_API_KEY") or None,
)


def _to_analyzer_request(request: AnalyzeRequest) -> AnalyzerRequest:
    """Map the API's request onto the analyzer's.

    `url` (the original single-URL field) and `links` (the richer anchor list)
    are merged, so callers on either shape work.
    """
    links = [AnalyzerLink(href=l.href, text=l.text) for l in request.links]
    if request.url and not any(l.href == request.url for l in links):
        links.append(AnalyzerLink(href=request.url))

    return AnalyzerRequest(
        text=request.message,
        links=links,
        sender=request.sender,
        source=request.platform,
    )


def _to_response(result: AnalysisResult, message_id: str | None) -> AnalyzeResponse:
    """Map the analyzer's result onto the API's response.

    `reason.type` is the human-readable label, not the enum slug, because the
    frontend renders it directly as a heading.
    """
    return AnalyzeResponse(
        message_id=message_id,
        risk_score=result.risk_score,
        risk_level=result.risk_band,
        category=result.category_label,
        summary=result.headline,
        reasons=[
            RiskReason(
                type=factor.label,
                explanation=factor.explanation,
                evidence=factor.evidence,
                severity=factor.severity.value,
                contribution=factor.contribution,
                source=factor.source,
            )
            for factor in result.factors
        ],
        recommended_action=result.recommended_action,
        action=result.action,
        headline=result.headline,
        likely_goal=result.likely_goal,
        confidence=result.confidence,
        links=[
            LinkReport(
                url=link.url,
                display_text=link.display_text,
                domain=link.domain,
                verdict=link.verdict,
                reasons=link.reasons,
                checked_by=link.checked_by,
            )
            for link in result.links
        ],
        tone=ToneReport(**result.tone.model_dump()) if result.tone else None,
        analyzed_by=result.analyzed_by,
        degraded=result.degraded,
        cached=result.cached,
        analysis_ms=result.analysis_ms,
    )


def analyze_scam(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze one message. Synchronous, for FastAPI's sync endpoints."""
    if not GEMINI_API_KEY:
        raise AIServiceError("GEMINI_API_KEY is not set")

    try:
        result = _runtime.submit(
            _runtime.analyzer.analyze(_to_analyzer_request(request)),
            timeout=ANALYZE_TIMEOUT_S,
        )
    except TimeoutError as error:
        raise AIServiceError(
            f"Analysis timed out after {ANALYZE_TIMEOUT_S:.0f}s"
        ) from error
    except Exception as error:
        raise AIServiceError("Failed to analyze message") from error

    return _to_response(result, request.message_id)


def rate_limit_status() -> dict | None:
    """Remaining free-tier quota this minute, for /health."""
    # Health checks must keep working before local AI credentials are set.
    # Avoid constructing the provider here because it requires an API key.
    if not GEMINI_API_KEY:
        return None

    limiter = getattr(_runtime.analyzer.provider, "limiter", None)
    if limiter is None:
        return None
    used, capacity = limiter.snapshot()
    return {"used": used, "capacity": capacity, "window_seconds": 60}
