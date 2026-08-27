from pydantic import BaseModel, Field, HttpUrl
from datetime import datetime


class LinkInput(BaseModel):
    """An anchor exactly as it appeared on the page.

    `text` is what the user sees, `href` is where it actually goes. When those
    disagree it is the single strongest scam signal we can compute -- and only
    the content script can see it, so please send both.
    """

    href: str
    text: str | None = None


class AnalyzeRequest(BaseModel):
    message: str = Field(min_length=1)

    sender: str | None = None
    url: str | None = None

    # Preferred over `url`: carries every anchor plus its display text.
    # `url` still works and is merged in, so existing callers are unaffected.
    links: list[LinkInput] = Field(default_factory=list)

    platform: str | None = None
    page_url: str | None = None
    message_id: str | None = None


class RiskReason(BaseModel):
    type: str
    explanation: str

    # Additive. `evidence` is a verbatim quote from the message that justifies
    # this reason -- showing it next to the text is what makes the analysis
    # believable rather than an opaque verdict.
    evidence: str | None = None
    severity: str | None = None
    contribution: int | None = None
    source: str | None = None


class LinkReport(BaseModel):
    """Per-URL verdict from the reputation checker (not from the model)."""

    url: str
    display_text: str | None = None
    domain: str | None = None
    verdict: str
    reasons: list[str] = Field(default_factory=list)
    checked_by: list[str] = Field(default_factory=list)


class ToneReport(BaseModel):
    """Manipulation analysis. Deliberately not plain positive/negative
    sentiment -- see the analyzer README for why that does not work here."""

    valence: str
    pressure: int
    fear: int
    greed: int
    authority: int
    summary: str


class AnalyzeResponse(BaseModel):
    message_id: str | None = None

    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    category: str
    summary: str
    reasons: list[RiskReason]
    recommended_action: str

    # ---- Additive fields. Every one is optional with a default, so existing
    # frontend code and the database writer keep working untouched. ----

    action: str | None = Field(
        None,
        description="allow | notice | warn | strong_warn | block -- maps 1:1 "
                    "to the extension's five UI states.",
    )
    headline: str | None = Field(None, description="One line for the warning badge.")
    likely_goal: str | None = None
    confidence: str | None = None
    links: list[LinkReport] = Field(default_factory=list)
    tone: ToneReport | None = None

    analyzed_by: str | None = Field(
        None, description="model | prefilter | link_check_only"
    )
    degraded: bool = False
    cached: bool = False
    analysis_ms: int | None = None

class AnalysisHistoryItem(BaseModel):
    id: int
    message: str
    sender: str | None
    url: str | None

    risk_score: int
    risk_level: str
    category: str
    summary: str
    reasons: list[RiskReason]
    recommended_action: str

    created_at: datetime

    model_config = {
        "from_attributes": True
    }

class BatchAnalyzeRequest(BaseModel):
    messages: list[AnalyzeRequest] = Field(
        min_length=1,
        max_length=50
    )

class BatchAnalyzeResponse(BaseModel):
    results: list[AnalyzeResponse]