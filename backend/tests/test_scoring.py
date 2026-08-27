"""Scoring maths -- the properties that keep the UI sane."""

from app.analyzer.categories import ScamCategory, Severity, Signal
from app.analyzer.scoring import apply_category_floor, band_for, score_signals


def s(sig, sev, src="model"):
    return (sig, sev, "quoted evidence", "because reasons", src)


def test_no_signals_is_zero():
    score, factors = score_signals([])
    assert score == 0 and factors == []
    assert band_for(0) == ("safe", "allow")


def test_single_critical_warns_but_does_not_block():
    score, _ = score_signals([s(Signal.CREDENTIAL_REQUEST, Severity.CRITICAL)])
    band, action = band_for(score)
    assert 70 <= score < 100
    assert action in ("warn", "strong_warn", "block")


def test_two_criticals_reach_block_territory():
    score, _ = score_signals([
        s(Signal.CREDENTIAL_REQUEST, Severity.CRITICAL),
        s(Signal.KNOWN_MALICIOUS_URL, Severity.CRITICAL, "link_check"),
    ])
    assert score >= 88
    assert band_for(score)[1] == "block"


def test_many_weak_signals_do_not_beat_one_strong_one():
    """The property that stops the extension crying wolf at bad grammar."""
    weak, _ = score_signals([
        s(Signal.POOR_GRAMMAR, Severity.LOW),
        s(Signal.GENERIC_GREETING, Severity.LOW),
        s(Signal.URGENCY, Severity.LOW),
        s(Signal.UNSOLICITED_CONTACT, Severity.LOW),
        s(Signal.PRIZE_CLAIM, Severity.LOW),
    ])
    strong, _ = score_signals([s(Signal.OTP_REQUEST, Severity.CRITICAL)])
    assert weak < strong
    assert band_for(weak)[1] in ("allow", "notice")


def test_duplicate_signals_collapse_to_highest_severity():
    once, _ = score_signals([s(Signal.URGENCY, Severity.HIGH)])
    thrice, _ = score_signals([
        s(Signal.URGENCY, Severity.LOW),
        s(Signal.URGENCY, Severity.HIGH),
        s(Signal.URGENCY, Severity.MEDIUM),
    ])
    assert once == thrice


def test_contributions_sum_to_score():
    """The Analyzer panel shows per-factor points; they must add up or the
    breakdown looks broken to anyone who checks."""
    score, factors = score_signals([
        s(Signal.IMPERSONATION, Severity.HIGH),
        s(Signal.URGENCY, Severity.MEDIUM),
        s(Signal.GIFT_CARD_REQUEST, Severity.CRITICAL),
        s(Signal.SECRECY, Severity.MEDIUM),
    ])
    assert abs(sum(f.contribution for f in factors) - score) <= len(factors)


def test_factors_are_ordered_by_importance():
    _, factors = score_signals([
        s(Signal.POOR_GRAMMAR, Severity.LOW),
        s(Signal.OTP_REQUEST, Severity.CRITICAL),
        s(Signal.URGENCY, Severity.MEDIUM),
    ])
    assert factors[0].signal == Signal.OTP_REQUEST
    assert [f.contribution for f in factors] == sorted(
        (f.contribution for f in factors), reverse=True
    )


def test_scoring_is_deterministic():
    inputs = [s(Signal.IMPERSONATION, Severity.HIGH), s(Signal.URGENCY, Severity.MEDIUM)]
    assert score_signals(inputs)[0] == score_signals(inputs)[0] == score_signals(inputs)[0]


def test_category_floor_lifts_weak_credential_theft():
    assert apply_category_floor(20, ScamCategory.CREDENTIAL_THEFT, has_signals=True) == 55


def test_category_floor_does_not_invent_risk_without_signals():
    assert apply_category_floor(0, ScamCategory.PHISHING, has_signals=False) == 0


def test_benign_has_no_floor():
    assert apply_category_floor(12, ScamCategory.BENIGN, has_signals=True) == 12


def test_all_bands_reachable():
    assert band_for(0) == ("safe", "allow")
    assert band_for(30) == ("low", "notice")
    assert band_for(60) == ("medium", "warn")
    assert band_for(80) == ("high", "strong_warn")
    assert band_for(95) == ("critical", "block")
