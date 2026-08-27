"""URL extraction, local heuristics, and Google Safe Browsing lookup.

Design note: link verdicts never come from the LLM. A model asked "is
evil-paypa1.ru dangerous?" will guess, and guesses are indistinguishable from
knowledge in the output. Everything here is either a deterministic rule or a
real reputation lookup, so every link reason is defensible.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx2 as httpx

from .categories import Severity, Signal
from .schema import LinkInput, LinkVerdict

SEVERITY_ORDER = {s: i for i, s in enumerate(Severity)}

SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

URL_RE = re.compile(
    r"""(?xi)
    \b
    (?:https?://|www\.)
    [^\s<>"'\)\]]+
    """
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in",
    "t.ly", "s.id", "bl.ink", "clck.ru", "surl.li",
}

# TLDs heavily over-represented in abuse feeds relative to legitimate traffic.
RISKY_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "gq", "cf", "tk", "ml", "ga",
    "work", "country", "kim", "science", "party", "review", "loan", "date",
    "stream", "download", "racing", "win", "bid", "rest", "cam", "quest",
}

# Brands most often impersonated. Used for look-alike detection only.
PROTECTED_BRANDS = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "icloud": "icloud.com",
    "microsoft": "microsoft.com",
    "office365": "office.com",
    "outlook": "outlook.com",
    "google": "google.com",
    "gmail": "gmail.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "linkedin": "linkedin.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "hsbc": "hsbc.com",
    "barclays": "barclays.co.uk",
    "revolut": "revolut.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "metamask": "metamask.io",
    "steam": "steampowered.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "usps": "usps.com",
    "irs": "irs.gov",
}

IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Single characters swapped in to fake a brand: paypa1.com, g00gle.com
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "$": "s", "@": "a"})

# Multi-character look-alikes. At small font sizes 'rn' is nearly identical to
# 'm' -- arnazon.com is a real, widely-used Amazon spoof. These cannot go in a
# str.maketrans table (that is strictly 1:1), so they are applied separately
# and both the substituted and unsubstituted forms are tested against brands.
HOMOGLYPH_PAIRS = (("rn", "m"), ("vv", "w"), ("nn", "m"))


@dataclass
class LinkFinding:
    """A link-derived signal, ready to merge into the score."""

    signal: Signal
    severity: Severity
    evidence: str
    explanation: str


def extract_urls(text: str) -> list[str]:
    """Pull bare URLs out of message text (anchors come in separately)."""
    out = []
    for raw in URL_RE.findall(text):
        url = raw.rstrip(".,;:!?)")
        if url.lower().startswith("www."):
            url = "http://" + url
        if url not in out:
            out.append(url)
    return out


def _registrable(host: str) -> str:
    """Approximate eTLD+1. Good enough for a hackathon; swap in `tldextract`
    if you hit a case like `foo.co.uk` being read as `co.uk`."""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _normalizations(name: str) -> set[str]:
    """Every plausible reading of a domain label a human eye might make.

    Both forms are kept: 'modern' should still read as 'modern', but
    'arnazon' must also be readable as 'amazon'.
    """
    base = name.translate(HOMOGLYPHS).replace("-", "")
    forms = {base}
    for pair, replacement in HOMOGLYPH_PAIRS:
        forms.update(f.replace(pair, replacement) for f in list(forms) if pair in f)
    return forms


def _lookalike_brand(host: str) -> str | None:
    """Return the brand this host is probably imitating, if any."""
    reg = _registrable(host)
    name = reg.split(".")[0]
    normalized_forms = _normalizations(name)

    for brand, official in PROTECTED_BRANDS.items():
        if reg == official or host == official or host.endswith("." + official):
            return None  # it *is* the brand
        # Brand name buried in a subdomain or path-like segment:
        # paypal.com.secure-verify.ru  /  login-paypal.example.net
        flat_host = host.replace(".", "").replace("-", "")
        if brand in flat_host or any(brand in f for f in normalized_forms):
            if reg != official:
                return brand
        # One-character typo or a homoglyph reading: paypa1.com, arnazon.com
        if any(
            len(f) >= 5 and _levenshtein(f, brand) <= 1
            for f in normalized_forms
        ):
            return brand
    return None


def inspect_url(url: str, display_text: str | None = None) -> tuple[LinkVerdict, list[LinkFinding]]:
    """Local, offline analysis of a single URL."""
    findings: list[LinkFinding] = []
    reasons: list[str] = []

    try:
        parsed = urlparse(url)
    except ValueError:
        return (
            LinkVerdict(url=url, display_text=display_text, verdict="suspicious",
                        reasons=["Malformed URL"], checked_by=["heuristics"]),
            [LinkFinding(Signal.SUSPICIOUS_LINK, Severity.MEDIUM, url, "This link is malformed.")],
        )

    host = (parsed.hostname or "").lower()
    domain = _registrable(host) if host else None
    verdict = "unrated"

    if "@" in (parsed.netloc or ""):
        reasons.append("URL hides its real destination behind an @ sign")
        findings.append(LinkFinding(
            Signal.SUSPICIOUS_LINK, Severity.HIGH, url,
            "The part before the @ is decoration -- the real destination is after it.",
        ))
        verdict = "suspicious"

    if IP_HOST_RE.match(host):
        reasons.append("Points at a raw IP address instead of a domain name")
        findings.append(LinkFinding(
            Signal.RAW_IP_LINK, Severity.HIGH, url,
            "Real companies use domain names; a bare IP address usually means an ad-hoc server.",
        ))
        verdict = "suspicious"

    if host.startswith("xn--") or ".xn--" in host:
        reasons.append("Uses punycode, which can disguise the domain name")
        findings.append(LinkFinding(
            Signal.LOOKALIKE_DOMAIN, Severity.HIGH, url,
            "This domain uses characters that look like ordinary letters but aren't.",
        ))
        verdict = "suspicious"

    if domain in SHORTENERS:
        reasons.append(f"Shortened via {domain} -- the destination is hidden")
        findings.append(LinkFinding(
            Signal.URL_SHORTENER, Severity.MEDIUM, url,
            f"{domain} hides where this link actually goes.",
        ))
        verdict = "suspicious" if verdict == "unrated" else verdict

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        reasons.append(f".{tld} domains are disproportionately used in abuse")
        findings.append(LinkFinding(
            Signal.SUSPICIOUS_LINK, Severity.MEDIUM, url,
            f"The .{tld} domain ending is heavily used by scam sites.",
        ))

    brand = _lookalike_brand(host)
    if brand:
        reasons.append(f"Imitates {brand} but is not {PROTECTED_BRANDS[brand]}")
        findings.append(LinkFinding(
            Signal.LOOKALIKE_DOMAIN, Severity.CRITICAL, url,
            f"This looks like {brand} but the real domain is {PROTECTED_BRANDS[brand]}.",
        ))
        verdict = "malicious"

    if host.count(".") >= 4:
        reasons.append("Unusually deep subdomain chain")
        findings.append(LinkFinding(
            Signal.SUSPICIOUS_LINK, Severity.LOW, url,
            "Long subdomain chains are used to make a bad domain look familiar.",
        ))

    # The strongest single signal we can compute: the anchor lies.
    if display_text:
        shown = display_text.strip().lower().rstrip("/")
        looks_like_url = "." in shown and " " not in shown
        if looks_like_url:
            shown_host = shown.split("//")[-1].split("/")[0]
            if shown_host and domain and _registrable(shown_host) != domain:
                reasons.append(f"Displays '{shown_host}' but goes to {domain}")
                findings.append(LinkFinding(
                    Signal.LINK_TEXT_MISMATCH, Severity.CRITICAL, display_text,
                    f"The link says {shown_host} but it actually goes to {domain}.",
                ))
                verdict = "malicious"

    # A URL that produced findings must not report as "unrated" -- the whole
    # point of the verdict is to summarise the findings, and leaving it unrated
    # meant a risky-TLD-plus-deep-subdomain URL rendered as if unexamined.
    if verdict == "unrated":
        worst = max(
            (SEVERITY_ORDER[f.severity] for f in findings), default=-1
        )
        if worst >= SEVERITY_ORDER[Severity.MEDIUM]:
            verdict = "suspicious"
        elif reasons:
            verdict = "suspicious"
        elif parsed.scheme == "https":
            verdict = "safe"

    return (
        LinkVerdict(url=url, display_text=display_text, domain=domain,
                    verdict=verdict, reasons=reasons, checked_by=["heuristics"]),
        findings,
    )


async def safe_browsing_lookup(urls: list[str], api_key: str, timeout: float = 3.0) -> set[str]:
    """Return the subset of `urls` Google flags as threats.

    Fails open: a network error or a bad key returns an empty set and the
    heuristics still stand. Never let a third-party outage break the demo.
    """
    if not urls or not api_key:
        return set()

    payload = {
        "client": {"clientId": "scam-guard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls[:500]],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                SAFE_BROWSING_ENDPOINT, params={"key": api_key}, json=payload
            )
            resp.raise_for_status()
            matches = resp.json().get("matches", [])
    except Exception:
        return set()
    return {m["threat"]["url"] for m in matches if "threat" in m}


async def check_links(
    text: str, links: list[LinkInput], api_key: str | None = None
) -> tuple[list[LinkVerdict], list[LinkFinding]]:
    """Full link pass: anchors from the DOM + bare URLs from the text."""
    api_key = api_key if api_key is not None else os.getenv("SAFE_BROWSING_API_KEY", "")

    candidates: dict[str, str | None] = {}
    for link in links:
        candidates.setdefault(link.href, link.text)
    for url in extract_urls(text):
        candidates.setdefault(url, None)

    if not candidates:
        return [], []

    verdicts: list[LinkVerdict] = []
    findings: list[LinkFinding] = []
    for url, display in candidates.items():
        verdict, found = inspect_url(url, display)
        verdicts.append(verdict)
        findings.extend(found)

    flagged = await safe_browsing_lookup(list(candidates), api_key)
    for verdict in verdicts:
        if api_key:
            verdict.checked_by.append("safe_browsing")
        if verdict.url in flagged:
            verdict.verdict = "malicious"
            verdict.reasons.insert(0, "Listed by Google Safe Browsing as a known threat")
            findings.append(LinkFinding(
                Signal.KNOWN_MALICIOUS_URL, Severity.CRITICAL, verdict.url,
                "Google Safe Browsing lists this exact link as malicious.",
            ))

    return verdicts, findings
