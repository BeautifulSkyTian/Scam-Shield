"""Verify the link checker on its own -- no AI, no message, just URLs.

    python -m tools.check_links                          # run the built-in suite
    python -m tools.check_links http://paypa1.xyz/login  # check specific URLs
    python -m tools.check_links --anchor "paypal.com" http://evil.xyz/go
    python -m tools.check_links --safe-browsing          # also hit Google's API

The heuristics half is fully offline and deterministic, so the built-in suite
is a real pass/fail check you can run with no network and no keys.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from dotenv import load_dotenv

load_dotenv()

from app.analyzer.links import check_links, inspect_url  # noqa: E402
from app.analyzer.schema import LinkInput  # noqa: E402

G, R, Y, D, B, RESET = ("\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m")

# (url, anchor text, expected verdict, what it is testing)
SUITE: list[tuple[str, str | None, str, str]] = [
    # --- should be flagged ---
    ("http://paypa1-resolution.xyz/cancel", "paypal.com/cancel", "malicious",
     "anchor text lies about the destination"),
    ("http://paypa1.com/login", None, "malicious",
     "typo-squat: digit 1 substituted for letter l"),
    ("http://paypal.com.secure-verify.ru/login", None, "malicious",
     "real brand buried in a subdomain of an attacker domain"),
    ("http://arnazon.com/orders", None, "malicious",
     "homoglyph: 'rn' reads as 'm'"),
    ("http://chase-secure-verify.tk/login", None, "malicious",
     "brand name plus throwaway TLD"),
    ("http://192.168.44.19/wallet-recovery", None, "suspicious",
     "raw IP address instead of a domain"),
    ("http://paypal.com@evil.example.net/login", None, "suspicious",
     "@ trick: real destination is after the @"),
    ("https://bit.ly/3xample", None, "suspicious",
     "shortener hides the destination"),
    ("http://xn--pypal-4ve.com/login", None, "suspicious",
     "punycode homograph domain"),
    ("http://a.b.c.d.e.example.top/login", None, "suspicious",
     "deep subdomain chain plus risky TLD"),

    # --- should NOT be flagged (the important half) ---
    ("https://github.com/password_reset/confirm", "Reset your password", "safe",
     "genuine password reset"),
    ("https://mail.google.com/mail/u/0", None, "safe",
     "real Google subdomain"),
    ("https://www.paypal.com/signin", None, "safe",
     "the actual brand domain"),
    ("https://shop.example-store.com/sale", "Shop now", "safe",
     "ordinary marketing link, anchor is not a URL"),
    ("https://github.com/settings", "github.com/settings", "safe",
     "anchor text matches the destination"),
    ("https://bbc.co.uk/news", None, "safe",
     "compound TLD must not be misread as the registrable domain"),
]


def run_suite() -> int:
    print(f"\n{B}Link checker — offline heuristics{RESET}")
    print(f"{D}No network, no API key. Deterministic: same result every run.{RESET}\n")

    failures = 0
    for url, anchor, expected, description in SUITE:
        verdict, findings = inspect_url(url, anchor)
        flagged = verdict.verdict in ("suspicious", "malicious")
        want_flagged = expected in ("suspicious", "malicious")
        ok = flagged == want_flagged

        if not ok:
            failures += 1
        mark = f"{G}ok  {RESET}" if ok else f"{R}FAIL{RESET}"
        print(f"  {mark} {verdict.verdict:<11} {url[:52]:<52} {D}{description}{RESET}")
        if anchor:
            print(f"       {D}shown to user as: \"{anchor}\"{RESET}")
        for finding in findings:
            print(f"       {Y}→{RESET} {finding.signal.value} "
                  f"({finding.severity.value}): {finding.explanation}")
        if not ok:
            print(f"       {R}expected {expected}, got {verdict.verdict}{RESET}")
        print()

    total = len(SUITE)
    print(f"  {total - failures}/{total} correct")
    if failures:
        print(f"  {R}{failures} failure(s){RESET}")
    return 1 if failures else 0


async def check_specific(urls: list[str], anchor: str | None, use_sb: bool) -> int:
    key = os.getenv("SAFE_BROWSING_API_KEY", "") if use_sb else ""
    if use_sb and not key:
        print(f"{Y}SAFE_BROWSING_API_KEY is not set — heuristics only.{RESET}")
        print(f"{D}Get a free key: console.cloud.google.com → enable "
              f"'Safe Browsing API' → create an API key → put it in .env{RESET}\n")

    links = [LinkInput(href=u, text=anchor) for u in urls]
    verdicts, findings = await check_links("", links, key)

    for verdict in verdicts:
        colour = {"malicious": R, "suspicious": Y, "safe": G}.get(verdict.verdict, "")
        print(f"\n  {colour}{B}{verdict.verdict.upper()}{RESET}  {verdict.url}")
        print(f"  {D}domain: {verdict.domain}  |  checked by: "
              f"{', '.join(verdict.checked_by)}{RESET}")
        for reason in verdict.reasons:
            print(f"    {Y}•{RESET} {reason}")
        if not verdict.reasons:
            print(f"    {D}nothing suspicious found{RESET}")

    if findings:
        print(f"\n  {B}Signals this contributes to the risk score{RESET}")
        for f in findings:
            print(f"    {f.signal.value} ({f.severity.value}) — {f.explanation}")
    print()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("urls", nargs="*", help="URLs to check (default: run the suite)")
    ap.add_argument("--anchor", help="Link text the user would see")
    ap.add_argument("--safe-browsing", action="store_true",
                    help="Also query Google Safe Browsing (needs a key)")
    args = ap.parse_args()

    if not args.urls:
        return run_suite()
    return asyncio.run(check_specific(args.urls, args.anchor, args.safe_browsing))


if __name__ == "__main__":
    sys.exit(main())
