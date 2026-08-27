"""Engine assembly and degraded-mode behaviour. No network."""

import asyncio

from app.analyzer.categories import ScamCategory, Severity, Signal
from app.analyzer.engine import ScamAnalyzer
from app.analyzer.links import LinkFinding
from app.analyzer.schema import (
    AnalyzeRequest, LinkVerdict, ModelSignal, ModelVerdict, ToneAnalysis,
)


def _tone():
    return ToneAnalysis(valence="negative", pressure=90, fear=80, greed=0,
                        authority=70, summary="Fear and deadline pressure.")


def _analyzer():
    return ScamAnalyzer.__new__(ScamAnalyzer)  # no client, no key


def test_degraded_mode_still_returns_a_usable_result():
    a = _analyzer()
    res = a._assemble(
        None,
        [LinkVerdict(url="http://192.168.1.1/x", verdict="suspicious",
                     reasons=["raw IP"], checked_by=["heuristics"])],
        [LinkFinding(Signal.RAW_IP_LINK, Severity.HIGH, "http://192.168.1.1/x", "Raw IP.")],
    )
    assert res.degraded is True
    assert res.risk_score > 0
    assert res.recommended_action
    assert res.tone is None


def test_benign_message_with_no_signals_scores_zero():
    a = _analyzer()
    res = a._assemble(
        ModelVerdict(category=ScamCategory.BENIGN, signals=[], tone=_tone(),
                     likely_goal="Nothing", confidence="high"),
        [], [],
    )
    assert res.risk_score == 0
    assert res.action == "allow"
    assert res.headline == "No scam indicators found"


def test_model_link_signals_are_dropped_in_favour_of_link_check():
    """The model was told not to emit these. If it does, we must not
    double-count the same URL as both a model signal and a link finding."""
    a = _analyzer()
    with_dup = a._assemble(
        ModelVerdict(
            category=ScamCategory.PHISHING,
            signals=[ModelSignal(signal=Signal.LOOKALIKE_DOMAIN, severity=Severity.CRITICAL,
                                 evidence="paypa1.com", explanation="Fake domain.")],
            tone=_tone(), likely_goal="Steal credentials", confidence="high"),
        [], [LinkFinding(Signal.LOOKALIKE_DOMAIN, Severity.CRITICAL, "paypa1.com", "Fake.")],
    )
    without = a._assemble(
        ModelVerdict(category=ScamCategory.PHISHING, signals=[], tone=_tone(),
                     likely_goal="Steal credentials", confidence="high"),
        [], [LinkFinding(Signal.LOOKALIKE_DOMAIN, Severity.CRITICAL, "paypa1.com", "Fake.")],
    )
    assert with_dup.risk_score == without.risk_score
    assert len([f for f in with_dup.factors if f.signal == Signal.LOOKALIKE_DOMAIN]) == 1


def test_factor_sources_are_attributed():
    a = _analyzer()
    res = a._assemble(
        ModelVerdict(
            category=ScamCategory.PHISHING,
            signals=[ModelSignal(signal=Signal.URGENCY, severity=Severity.HIGH,
                                 evidence="within 24 hours", explanation="Deadline pressure.")],
            tone=_tone(), likely_goal="Steal credentials", confidence="high"),
        [], [LinkFinding(Signal.RAW_IP_LINK, Severity.HIGH, "http://1.2.3.4", "Raw IP.")],
    )
    by_signal = {f.signal: f.source for f in res.factors}
    assert by_signal[Signal.URGENCY] == "model"
    assert by_signal[Signal.RAW_IP_LINK] == "link_check"


def test_result_serialises_to_json():
    a = _analyzer()
    res = a._assemble(
        ModelVerdict(category=ScamCategory.BENIGN, signals=[], tone=_tone(),
                     likely_goal="none", confidence="high"), [], [])
    payload = res.model_dump(mode="json")
    assert payload["schema_version"] == "1.0"
    assert isinstance(payload["risk_score"], int)
