"""The contract.

Everything crossing a process boundary is defined here:
  extension -> backend   : AnalyzeRequest
  backend   -> extension : AnalysisResult
  Claude    -> analyzer  : ModelVerdict  (never leaves the process)

Person 1/2/3: code against AnalysisResult only. It is stable; the internals
behind it are not.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .categories import ScamCategory, Severity, Signal

SCHEMA_VERSION = "1.0"


# --------------------------------------------------------------------------
# Input
# --------------------------------------------------------------------------

class LinkInput(BaseModel):
    """An anchor as it appeared on the page.

    `text` matters: "paypal.com" pointing at evil.ru is one of the strongest
    signals we have, and only the content script can see it.
    """

    href: str
    text: str | None = None


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20_000)
    links: list[LinkInput] = Field(default_factory=list)
    sender: str | None = Field(
        None, description="Email address, phone number, or @handle if visible."
    )
    subject: str | None = None
    source: str | None = Field(
        None, description="Where it came from, e.g. 'gmail', 'whatsapp', 'linkedin'."
    )


# --------------------------------------------------------------------------
# What Claude returns (internal)
# --------------------------------------------------------------------------

class ModelSignal(BaseModel):
    """One observation, with the evidence that justifies it.

    `evidence` must be a verbatim quote from the message. That single
    constraint is what makes the Analyzer panel trustworthy -- every chip in
    the UI can be traced back to text the user can re-read.
    """

    signal: Signal
    severity: Severity
    evidence: str = Field(..., description="Verbatim quote from the message.")
    explanation: str = Field(..., description="One sentence, addressed to the user.")


class ToneAnalysis(BaseModel):
    """The 'sentiment' layer -- reframed as manipulation analysis.

    Plain positive/negative sentiment does not separate scams from legitimate
    messages. Pressure tactics do, so that is what we measure.
    """

    valence: Literal["positive", "neutral", "negative"]
    pressure: int = Field(..., ge=0, le=100, description="How hard it pushes you to act now.")
    fear: int = Field(..., ge=0, le=100)
    greed: int = Field(..., ge=0, le=100)
    authority: int = Field(..., ge=0, le=100)
    summary: str = Field(..., description="One sentence on the emotional strategy.")


class ModelVerdict(BaseModel):
    """Exactly what we ask Claude for. No risk number -- Python owns that."""

    category: ScamCategory
    signals: list[ModelSignal]
    tone: ToneAnalysis
    likely_goal: str = Field(..., description="What the sender is actually after.")
    confidence: Literal["low", "medium", "high"]


# --------------------------------------------------------------------------
# Output (public)
# --------------------------------------------------------------------------

Action = Literal["allow", "notice", "warn", "strong_warn", "block"]


class RiskFactor(BaseModel):
    """A scored signal, ready to render as a UI chip."""

    signal: Signal
    label: str
    severity: Severity
    evidence: str
    explanation: str
    contribution: int = Field(..., ge=0, le=100, description="Points this added to the score.")
    source: Literal["model", "link_check", "heuristic"] = "model"


class LinkVerdict(BaseModel):
    url: str
    display_text: str | None = None
    domain: str | None = None
    verdict: Literal["safe", "unrated", "suspicious", "malicious"]
    reasons: list[str] = Field(default_factory=list)
    checked_by: list[str] = Field(default_factory=list, description="e.g. ['heuristics', 'safe_browsing']")


class AnalysisResult(BaseModel):
    schema_version: str = SCHEMA_VERSION
    risk_score: int = Field(..., ge=0, le=100)
    risk_band: Literal["safe", "low", "medium", "high", "critical"]
    action: Action
    category: ScamCategory
    category_label: str
    headline: str = Field(..., description="One line for the warning badge.")
    likely_goal: str | None = None
    confidence: Literal["low", "medium", "high"]
    factors: list[RiskFactor] = Field(default_factory=list)
    links: list[LinkVerdict] = Field(default_factory=list)
    tone: ToneAnalysis | None = None
    recommended_action: str = Field(..., description="What the user should do, in plain words.")
    analysis_ms: int = 0
    analyzed_by: Literal["model", "prefilter", "link_check_only"] = Field(
        "model",
        description=(
            "How this verdict was reached. 'prefilter' means no API call was "
            "made because nothing in the message could plausibly be a scam."
        ),
    )
    degraded: bool = Field(
        False, description="True if the AI call failed and this is heuristics-only."
    )
    cached: bool = False
