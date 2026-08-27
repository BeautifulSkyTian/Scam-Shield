"""Link heuristics -- fully offline, no API key required."""

import pytest

from app.analyzer.categories import Signal
from app.analyzer.links import extract_urls, inspect_url, _lookalike_brand, _registrable


def test_extract_urls_strips_trailing_punctuation():
    urls = extract_urls("Go to https://example.com/path, then www.foo.co.uk.")
    assert "https://example.com/path" in urls
    assert "http://www.foo.co.uk" in urls


def test_registrable_handles_compound_tlds():
    assert _registrable("mail.google.com") == "google.com"
    assert _registrable("shop.bbc.co.uk") == "bbc.co.uk"
    assert _registrable("example.com") == "example.com"


@pytest.mark.parametrize("host,brand", [
    ("paypa1.com", "paypal"),
    ("paypal.com.secure-verify.ru", "paypal"),
    ("login-microsoft.evil.xyz", "microsoft"),
    ("chase-secure-verify.tk", "chase"),
])
def test_lookalike_detected(host, brand):
    assert _lookalike_brand(host) == brand


@pytest.mark.parametrize("host", [
    "paypal.com", "www.paypal.com", "github.com", "mail.google.com", "example.com",
])
def test_real_domains_not_flagged(host):
    assert _lookalike_brand(host) is None


def test_anchor_text_mismatch_is_critical():
    verdict, findings = inspect_url("http://paypa1-resolution.xyz/cancel", "paypal.com/cancel")
    assert verdict.verdict == "malicious"
    assert Signal.LINK_TEXT_MISMATCH in {f.signal for f in findings}


def test_matching_anchor_text_is_clean():
    verdict, findings = inspect_url("https://github.com/settings", "github.com/settings")
    assert Signal.LINK_TEXT_MISMATCH not in {f.signal for f in findings}


def test_raw_ip_link():
    verdict, findings = inspect_url("http://192.168.44.19/wallet-recovery")
    assert Signal.RAW_IP_LINK in {f.signal for f in findings}
    assert verdict.verdict == "suspicious"


def test_shortener_flagged_but_only_medium():
    verdict, findings = inspect_url("https://bit.ly/3xample")
    signals = {f.signal: f.severity for f in findings}
    assert Signal.URL_SHORTENER in signals
    assert signals[Signal.URL_SHORTENER].value == "medium"


def test_ordinary_https_link_is_safe():
    verdict, findings = inspect_url("https://shop.example-store.com/sale", "Shop now")
    assert verdict.verdict == "safe"
    assert findings == []


def test_at_sign_obfuscation():
    verdict, findings = inspect_url("http://paypal.com@evil.example.net/login")
    assert verdict.domain == "example.net"
    assert Signal.SUSPICIOUS_LINK in {f.signal for f in findings}


# --- Regressions found by tools/check_links.py -----------------------------

@pytest.mark.parametrize("host,brand", [
    ("arnazon.com", "amazon"),      # 'rn' reads as 'm' at small sizes
    ("paypa1.com", "paypal"),
    ("app1e.com", "apple"),
])
def test_multichar_homoglyphs_detected(host, brand):
    assert _lookalike_brand(host) == brand


@pytest.mark.parametrize("host", [
    "modern-recipes.com",   # contains 'rn' but is not a brand spoof
    "google.com", "mail.google.com", "github.com", "bbc.co.uk",
    "www.paypal.com", "example-store.com", "vendorco.com",
])
def test_homoglyph_normalisation_does_not_create_false_positives(host):
    """The 'rn'->'m' rewrite must not start flagging ordinary domains."""
    assert _lookalike_brand(host) is None


def test_url_with_findings_is_never_reported_as_unrated():
    """A URL that produced findings must summarise them in its verdict --
    'unrated' told the UI nothing had been examined, which was a lie."""
    verdict, findings = inspect_url("http://a.b.c.d.e.example.top/login")
    assert findings, "expected risky-TLD and deep-subdomain findings"
    assert verdict.verdict == "suspicious"
    assert verdict.verdict != "unrated"


def test_clean_https_link_still_reports_safe():
    verdict, findings = inspect_url("https://mail.google.com/mail/u/0")
    assert verdict.verdict == "safe" and not findings
