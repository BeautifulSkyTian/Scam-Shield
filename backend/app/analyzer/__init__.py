"""AI scam analysis layer for the message-filtering extension."""

from .categories import ScamCategory, Severity, Signal
from .engine import ScamAnalyzer
from .providers import GeminiProvider, build_provider
from .schema import (
    SCHEMA_VERSION,
    AnalysisResult,
    AnalyzeRequest,
    LinkInput,
    LinkVerdict,
    RiskFactor,
    ToneAnalysis,
)

__all__ = [
    "ScamAnalyzer",
    "build_provider",
    "GeminiProvider",
    "AnalyzeRequest",
    "AnalysisResult",
    "LinkInput",
    "LinkVerdict",
    "RiskFactor",
    "ToneAnalysis",
    "ScamCategory",
    "Signal",
    "Severity",
    "SCHEMA_VERSION",
]

from .runtime import AnalyzerRuntime  # noqa: E402

__all__.append("AnalyzerRuntime")
