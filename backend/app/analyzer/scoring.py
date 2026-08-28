"""Deterministic risk scoring.

Same signals in => same score out, every time. The model contributes
observations; this file contributes the number. That split is what lets you
tune behaviour during a demo without touching a prompt, and what makes the
eval suite meaningful.

Combination rule: noisy-OR.

    P(scam) = 1 - PROD(1 - w_i)

Each signal is treated as independent evidence. Consequences that matter:
  * one CRITICAL signal alone lands ~62 -- a real warning, not a block
  * two independent CRITICAL signals land ~86 -- block territory
  * six LOW signals land ~26 -- still only "notice", which is correct;
    a pile of weak hints should not equal a stolen-password request
"""

from __future__ import annotations

from .categories import (
    CATEGORY_LABELS,
    SEVERITY_WEIGHT,
    SIGNAL_LABELS,
    SIGNAL_WEIGHT,
    ScamCategory,
    Severity,
    Signal,
)
from .schema import Action, RiskFactor

# Band edges. Tuned so that "one strong signal" != "block the page".
BANDS: list[tuple[int, str, Action]] = [
    (25, "safe", "allow"),
    (45, "low", "notice"),
    (70, "medium", "warn"),
    (88, "high", "strong_warn"),
    (101, "critical", "block"),
]

RECOMMENDED_ACTION = {
    "allow": "Nothing suspicious stood out. Carry on as normal.",
    "notice": "Probably fine, but don't act on anything urgent in it without checking.",
    "warn": "Treat this as untrustworthy. Don't click links or reply with any details.",
    "strong_warn": "This is very likely a scam. Don't click anything, don't reply, and delete it.",
    "block": "Do not interact with this message. Report it and delete it. If you already "
             "clicked or entered details, change that password now.",
}

# A category cannot on its own make a message dangerous, but it caps how low
# the score can be read as: an identified credential-theft attempt with weak
# signals is still worth a warning.
CATEGORY_FLOOR = {
    ScamCategory.CREDENTIAL_THEFT: 55,
    ScamCategory.PHISHING: 50,
    ScamCategory.MALWARE: 60,
    ScamCategory.TECH_SUPPORT: 45,
    ScamCategory.ADVANCE_FEE: 45,
    ScamCategory.ROMANCE: 40,
    ScamCategory.INVESTMENT_CRYPTO: 45,
    ScamCategory.JOB_SCAM: 40,
    ScamCategory.IMPERSONATION: 40,
    ScamCategory.FINANCIAL_SCAM: 45,
    ScamCategory.SOCIAL_ENGINEERING: 35,
    ScamCategory.SPAM: 0,
    ScamCategory.BENIGN: 0,
}


def signal_weight(signal: Signal, severity: Severity) -> float:
    """Weight of one signal in [0, 0.95]."""
    w = SEVERITY_WEIGHT[severity] * SIGNAL_WEIGHT.get(signal, 1.0)
    return min(w, 0.95)


def score_signals(
    scored: list[tuple[Signal, Severity, str, str, str]],
) -> tuple[int, list[RiskFactor]]:
    """Combine signals into a 0-100 score plus per-factor attribution.

    `scored` items are (signal, severity, evidence, explanation, source).
    Duplicate signal types collapse to their highest severity -- three
    separate "urgency" observations are one urgency signal, not three.
    """
    best: dict[Signal, tuple[Severity, str, str, str]] = {}
    order = list(Severity)
    for sig, sev, evidence, explanation, source in scored:
        prev = best.get(sig)
        if prev is None or order.index(sev) > order.index(prev[0]):
            best[sig] = (sev, evidence, explanation, source)

    weighted = sorted(
        ((sig, *rest) for sig, rest in best.items()),
        key=lambda item: signal_weight(item[0], item[1]),
        reverse=True,
    )

    survival = 1.0
    factors: list[RiskFactor] = []
    for sig, sev, evidence, explanation, source in weighted:
        w = signal_weight(sig, sev)
        before = 1.0 - survival
        survival *= 1.0 - w
        after = 1.0 - survival
        factors.append(
            RiskFactor(
                signal=sig,
                label=SIGNAL_LABELS.get(sig, sig.value.replace("_", " ").title()),
                severity=sev,
                evidence=evidence,
                explanation=explanation,
                # Marginal contribution: what this signal added given everything
                # ranked above it. Sums to the total, so the panel adds up.
                contribution=round((after - before) * 100),
                source=source,  # type: ignore[arg-type]
            )
        )

    return round((1.0 - survival) * 100), factors


def apply_category_floor(score: int, category: ScamCategory, has_signals: bool) -> int:
    """Don't let a confidently-identified scam type score as harmless."""
    if not has_signals:
        return score
    return max(score, CATEGORY_FLOOR.get(category, 0))


def band_for(score: int) -> tuple[str, Action]:
    for edge, band, action in BANDS:
        if score < edge:
            return band, action
    return "critical", "block"


def headline_for(score: int, category: ScamCategory, factors: list[RiskFactor]) -> str:
    """One line for the badge. Person 2 renders this verbatim."""
    if category in (ScamCategory.BENIGN, ScamCategory.SPAM) and score < 25:
        return "No scam indicators found"
    label = CATEGORY_LABELS.get(category, "Suspicious message")
    top = factors[0].label.lower() if factors else "multiple risk indicators"
    if score >= 88:
        return f"Almost certainly {label.lower()} — {top}"
    if score >= 70:
        return f"Likely {label.lower()} — {top}"
    if score >= 45:
        return f"Possible {label.lower()} — {top}"
    return f"Minor concerns — {top}"
