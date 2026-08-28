"""Scam taxonomy and signal weights.

This is the tuning surface of the whole system. If the demo mis-scores a
message, you change a number here -- not a prompt, not the model.
"""

from enum import Enum


class ScamCategory(str, Enum):
    """What kind of scam this is, if it is one."""

    BENIGN = "benign"
    SPAM = "spam"
    PHISHING = "phishing"
    IMPERSONATION = "impersonation"
    CREDENTIAL_THEFT = "credential_theft"
    FINANCIAL_SCAM = "financial_scam"
    ADVANCE_FEE = "advance_fee"
    INVESTMENT_CRYPTO = "investment_crypto_scam"
    ROMANCE = "romance_scam"
    TECH_SUPPORT = "tech_support_scam"
    JOB_SCAM = "job_scam"
    MALWARE = "malware"
    SOCIAL_ENGINEERING = "social_engineering"


CATEGORY_LABELS = {
    ScamCategory.BENIGN: "No scam detected",
    ScamCategory.SPAM: "Unwanted spam",
    ScamCategory.PHISHING: "Phishing",
    ScamCategory.IMPERSONATION: "Impersonation",
    ScamCategory.CREDENTIAL_THEFT: "Credential theft",
    ScamCategory.FINANCIAL_SCAM: "Financial scam",
    ScamCategory.ADVANCE_FEE: "Advance-fee scam",
    ScamCategory.INVESTMENT_CRYPTO: "Investment / crypto scam",
    ScamCategory.ROMANCE: "Romance scam",
    ScamCategory.TECH_SUPPORT: "Tech-support scam",
    ScamCategory.JOB_SCAM: "Fake job offer",
    ScamCategory.MALWARE: "Malware delivery",
    ScamCategory.SOCIAL_ENGINEERING: "Social engineering",
}


class Signal(str, Enum):
    """Atomic observations. The model emits these; Python scores them.

    Keep this list closed -- an open-ended `reason: str` cannot be scored,
    tested, or shown as a consistent UI chip.
    """

    # Pressure / manipulation
    URGENCY = "urgency"
    THREAT = "threat"
    AUTHORITY_PRESSURE = "authority_pressure"
    SECRECY = "secrecy"
    TOO_GOOD_TO_BE_TRUE = "too_good_to_be_true"
    EMOTIONAL_MANIPULATION = "emotional_manipulation"

    # Identity
    IMPERSONATION = "impersonation"
    SENDER_MISMATCH = "sender_mismatch"
    UNSOLICITED_CONTACT = "unsolicited_contact"

    # The ask
    CREDENTIAL_REQUEST = "credential_request"
    OTP_REQUEST = "otp_request"
    PAYMENT_REQUEST = "payment_request"
    CRYPTO_REQUEST = "crypto_request"
    GIFT_CARD_REQUEST = "gift_card_request"
    PERSONAL_INFO_REQUEST = "personal_info_request"
    REMOTE_ACCESS_REQUEST = "remote_access_request"
    OFF_PLATFORM_MOVE = "off_platform_move"

    # Links / payload  (mostly emitted by links.py, not the model)
    SUSPICIOUS_LINK = "suspicious_link"
    LINK_TEXT_MISMATCH = "link_text_mismatch"
    LOOKALIKE_DOMAIN = "lookalike_domain"
    URL_SHORTENER = "url_shortener"
    RAW_IP_LINK = "raw_ip_link"
    KNOWN_MALICIOUS_URL = "known_malicious_url"
    ATTACHMENT_LURE = "attachment_lure"

    # Weak corroborating signals
    POOR_GRAMMAR = "poor_grammar"
    GENERIC_GREETING = "generic_greeting"
    PRIZE_CLAIM = "prize_claim"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# How much a signal at a given severity contributes, as an independent
# probability-of-scam contribution in [0, 1). Combined with noisy-OR in
# scoring.py, so ten weak signals never beat one critical one by accident.
SEVERITY_WEIGHT = {
    Severity.LOW: 0.06,
    Severity.MEDIUM: 0.18,
    Severity.HIGH: 0.38,
    Severity.CRITICAL: 0.62,
}

# Per-signal multiplier on top of severity. Signals that are near-conclusive
# on their own get >1; signals that are common in legitimate mail get <1.
SIGNAL_WEIGHT = {
    Signal.KNOWN_MALICIOUS_URL: 1.6,
    Signal.CREDENTIAL_REQUEST: 1.5,
    Signal.OTP_REQUEST: 1.6,
    Signal.GIFT_CARD_REQUEST: 1.5,
    Signal.CRYPTO_REQUEST: 1.35,
    Signal.REMOTE_ACCESS_REQUEST: 1.4,
    Signal.LOOKALIKE_DOMAIN: 1.35,
    Signal.LINK_TEXT_MISMATCH: 1.3,
    Signal.IMPERSONATION: 1.2,
    Signal.SENDER_MISMATCH: 1.2,
    Signal.RAW_IP_LINK: 1.15,
    Signal.THREAT: 1.1,
    Signal.PAYMENT_REQUEST: 1.1,
    Signal.SUSPICIOUS_LINK: 1.0,
    Signal.PERSONAL_INFO_REQUEST: 1.0,
    Signal.ATTACHMENT_LURE: 1.0,
    Signal.SECRECY: 1.0,
    Signal.OFF_PLATFORM_MOVE: 1.0,
    Signal.TOO_GOOD_TO_BE_TRUE: 0.95,
    Signal.PRIZE_CLAIM: 0.95,
    Signal.AUTHORITY_PRESSURE: 0.9,
    Signal.EMOTIONAL_MANIPULATION: 0.85,
    Signal.URL_SHORTENER: 0.8,
    Signal.UNSOLICITED_CONTACT: 0.7,
    # Deliberately weak: legitimate mail is often urgent, badly written, or
    # addressed to "Dear Customer". These corroborate; they never convict.
    Signal.URGENCY: 0.65,
    Signal.POOR_GRAMMAR: 0.35,
    Signal.GENERIC_GREETING: 0.3,
}

# Human-readable chip labels for the extension UI (Person 2 consumes these).
SIGNAL_LABELS = {
    Signal.URGENCY: "Artificial urgency",
    Signal.THREAT: "Threat or consequence",
    Signal.AUTHORITY_PRESSURE: "Claims authority",
    Signal.SECRECY: "Asks you to keep it secret",
    Signal.TOO_GOOD_TO_BE_TRUE: "Too good to be true",
    Signal.EMOTIONAL_MANIPULATION: "Emotional manipulation",
    Signal.IMPERSONATION: "Impersonation",
    Signal.SENDER_MISMATCH: "Sender doesn't match claim",
    Signal.UNSOLICITED_CONTACT: "Unsolicited contact",
    Signal.CREDENTIAL_REQUEST: "Asks for password / login",
    Signal.OTP_REQUEST: "Asks for a verification code",
    Signal.PAYMENT_REQUEST: "Asks for payment or transfer",
    Signal.CRYPTO_REQUEST: "Asks for crypto",
    Signal.GIFT_CARD_REQUEST: "Asks for gift cards",
    Signal.PERSONAL_INFO_REQUEST: "Asks for personal details",
    Signal.REMOTE_ACCESS_REQUEST: "Asks for device access",
    Signal.OFF_PLATFORM_MOVE: "Pushes you off-platform",
    Signal.SUSPICIOUS_LINK: "Suspicious link",
    Signal.LINK_TEXT_MISMATCH: "Link text doesn't match destination",
    Signal.LOOKALIKE_DOMAIN: "Look-alike domain",
    Signal.URL_SHORTENER: "Shortened link hides destination",
    Signal.RAW_IP_LINK: "Link points at a raw IP address",
    Signal.KNOWN_MALICIOUS_URL: "Known malicious link",
    Signal.ATTACHMENT_LURE: "Pressures you to open an attachment",
    Signal.POOR_GRAMMAR: "Unprofessional writing",
    Signal.GENERIC_GREETING: "Generic greeting",
    Signal.PRIZE_CLAIM: "Unexpected prize or windfall",
}

# Signals that links.py produces from hard evidence. The model is told not to
# emit these -- we don't want it hallucinating URL verdicts it can't check.
LINK_OWNED_SIGNALS = {
    Signal.SUSPICIOUS_LINK,
    Signal.LINK_TEXT_MISMATCH,
    Signal.LOOKALIKE_DOMAIN,
    Signal.URL_SHORTENER,
    Signal.RAW_IP_LINK,
    Signal.KNOWN_MALICIOUS_URL,
}


# When to call each signal what. Without these the model anchors every signal
# to "medium" and the score collapses toward the middle -- the single biggest
# source of miscalibration in a signal-extraction classifier.
#
# Format: signal -> (what makes it low/medium, what makes it high/critical)
SEVERITY_ANCHORS = {
    Signal.URGENCY: (
        "a normal business deadline ('reply by Friday', 'action required')",
        "an artificial countdown with a penalty ('account closed in 2 hours')",
    ),
    Signal.THREAT: (
        "a routine consequence a real company would state ('service may be suspended')",
        "intimidation: arrest, legal action, account deletion, exposure of private data",
    ),
    Signal.AUTHORITY_PRESSURE: (
        "an ordinary corporate sender ('the billing team')",
        "invoking police, tax authorities, your CEO, or 'security' to stop you questioning it",
    ),
    Signal.SECRECY: (
        "ordinary confidentiality ('please don't forward')",
        "asking you to hide the request from colleagues, family, or your bank",
    ),
    Signal.TOO_GOOD_TO_BE_TRUE: (
        "an ordinary discount or promotion",
        "guaranteed returns, free money, or a reward wildly out of proportion to the effort",
    ),
    Signal.EMOTIONAL_MANIPULATION: (
        "friendly or warm phrasing",
        "manufactured intimacy, pity, romance, or a fabricated emergency to extract money",
    ),
    Signal.IMPERSONATION: (
        "a generic claim to represent a company",
        "claiming to be a specific named person or institution the recipient trusts "
        "(their bank, their CEO, a government body)",
    ),
    Signal.SENDER_MISMATCH: (
        "a sender address that is merely unfamiliar",
        "a sender domain that contradicts the claimed identity (a 'bank' mailing from gmail)",
    ),
    Signal.UNSOLICITED_CONTACT: (
        "marketing from a company the user plausibly deals with",
        "a total stranger opening with money, romance, or a job offer",
    ),
    Signal.CREDENTIAL_REQUEST: (
        "a login link for an action the user plausibly initiated (a reset they asked for)",
        "asking the user to supply, confirm, or re-enter an existing password, PIN, or "
        "security answer -- by reply OR through a link. Real services never do this",
    ),
    Signal.OTP_REQUEST: (
        "mentioning a code the user is expected to enter on the real site",
        "asking the user to send, share, read out, or reply with a code. This is always "
        "critical -- there is no legitimate reason to ask",
    ),
    Signal.PAYMENT_REQUEST: (
        "a normal invoice or renewal from a plausible counterparty",
        "an unexpected demand, a changed bank account, or an untraceable method "
        "(wire, Western Union, Zelle to a stranger)",
    ),
    Signal.CRYPTO_REQUEST: (
        "discussing crypto without asking for any",
        "asking for a transfer to a wallet, or for a seed phrase or private key",
    ),
    Signal.GIFT_CARD_REQUEST: (
        "mentioning gift cards as a product",
        "asking the user to buy cards and send codes. Effectively always critical -- "
        "no real organisation is paid this way",
    ),
    Signal.PERSONAL_INFO_REQUEST: (
        "asking for a name or an order number",
        "asking for date of birth, national ID, full card number, or bank details",
    ),
    Signal.REMOTE_ACCESS_REQUEST: (
        "offering a support call",
        "asking the user to install AnyDesk/TeamViewer or grant screen or device control",
    ),
    Signal.OFF_PLATFORM_MOVE: (
        "offering an alternative contact method alongside the official one",
        "insisting on WhatsApp/Telegram/personal email instead of the platform, "
        "especially where the platform would keep a record",
    ),
    Signal.ATTACHMENT_LURE: (
        "a routine attachment reference from a known counterparty",
        "pressure to open an unexpected attachment, or an executable/macro/archive",
    ),
    Signal.POOR_GRAMMAR: (
        "informal or sloppy writing -- extremely common in real messages",
        "reserve high for errors no real institution would ship in a template. "
        "Bad spelling alone is weak evidence: real people write badly",
    ),
    Signal.GENERIC_GREETING: (
        "'Hi' or no greeting at all",
        "'Dear Valued Customer' from an organisation that knows the user's name. "
        "Weak evidence on its own",
    ),
    Signal.PRIZE_CLAIM: (
        "a legitimate promotion the user could have entered",
        "an unsolicited win for a contest never entered, especially with a fee to claim",
    ),
}
