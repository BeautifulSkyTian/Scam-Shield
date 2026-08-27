"""Cheap local triage: decide whether a message is worth an API call.

On a 15-requests-per-minute free tier, every call spent on "hey, running 5
minutes late" is a call not available for the phishing email two rows down.
This filter answers one question -- "is there anything here that could
possibly be a scam?" -- and it is deliberately biased toward saying yes.

Skipping the model is only safe when the message has NO links and NOT ONE
word from the risk lexicon. Anything else goes to the model. A false "skip"
is a missed scam, so the lexicon errs heavily on the side of inclusion.
"""

from __future__ import annotations

import re

from .links import extract_urls

# Any one of these forces a full analysis. Over-inclusive on purpose: the
# cost of a needless API call is latency, the cost of a wrong skip is a
# scam reaching the user unflagged.
RISK_LEXICON = {
    # credentials / accounts
    "password", "passcode", "pin", "otp", "2fa", "verification code", "verify",
    "login", "log in", "sign in", "credentials", "account", "suspended",
    "locked", "unlock", "reactivate", "confirm your", "authenticate", "seed phrase",
    "recovery phrase", "private key", "wallet",
    # money
    "payment", "invoice", "refund", "transfer", "wire", "bank", "card",
    "billing", "charge", "transaction", "fee", "customs", "tax", "irs",
    "bitcoin", "btc", "crypto", "usdt", "eth", "gift card", "giftcard",
    "western union", "moneygram", "zelle", "paypal", "venmo", "cash app",
    "deposit", "withdraw", "investment", "profit", "returns",
    # pressure / lures
    "urgent", "immediately", "act now", "final notice", "last warning",
    "expires", "expiring", "within 24", "24 hours", "48 hours", "deadline",
    "suspend", "terminate", "closed", "penalty", "legal action", "arrest",
    "prize", "winner", "won", "lottery", "claim your", "congratulations",
    "selected", "free", "bonus", "reward", "inheritance", "beneficiary",
    # channel / access
    "click here", "click the link", "download", "attachment", "install",
    "anydesk", "teamviewer", "remote access", "whatsapp", "telegram",
    "text me", "call this number", "support team", "helpdesk",
    # identity
    "on behalf of", "ceo", "manager", "hr department", "security team",
    "microsoft", "apple", "amazon", "netflix", "google", "usps", "dhl", "fedex",
    # social engineering
    "keep this between", "don't tell", "confidential", "discreet", "secret",
    "trust me", "dear customer", "dear user", "dear sir", "valued customer",
}

_LEXICON_RE = re.compile(
    r"(?i)(?:^|\W)(" + "|".join(re.escape(t) for t in sorted(RISK_LEXICON, key=len, reverse=True)) + r")(?:\W|$)"
)

# A long message is worth analysing regardless -- scammers write essays.
LENGTH_ALWAYS_ANALYSE = 600


def matched_terms(text: str) -> list[str]:
    return sorted({m.group(1).lower() for m in _LEXICON_RE.finditer(text)})


def needs_model(text: str, links: list | None = None) -> tuple[bool, str]:
    """(should_call_model, why).

    `why` is logged and surfaced in the eval so a wrong skip is debuggable.
    """
    if links:
        return True, "message contains links"
    if extract_urls(text):
        return True, "message contains a URL"
    if len(text) >= LENGTH_ALWAYS_ANALYSE:
        return True, f"long message ({len(text)} chars)"
    if terms := matched_terms(text):
        return True, f"risk terms: {', '.join(terms[:5])}"
    return False, "no links and no risk vocabulary"
