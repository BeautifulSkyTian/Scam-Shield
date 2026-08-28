"""Analyse one message from the command line.

    python demo.py "URGENT: verify your password at http://chase-secure.tk"
    echo "some message" | python demo.py
    python demo.py --json "..."          # raw response, as the extension sees it

Useful for the live demo, and for sanity-checking a prompt change without
burning a full eval run.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from dotenv import load_dotenv

load_dotenv()

from app.analyzer import AnalyzeRequest, ScamAnalyzer  # noqa: E402

BAR = {"allow": "\033[32m", "notice": "\033[36m", "warn": "\033[33m",
       "strong_warn": "\033[31m", "block": "\033[41m\033[97m"}
RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("message", nargs="*", help="Message text (or pipe via stdin)")
    ap.add_argument("--sender")
    ap.add_argument("--json", action="store_true", help="Print the raw API response")
    args = ap.parse_args()

    text = " ".join(args.message) or sys.stdin.read().strip()
    if not text:
        ap.error("no message given")

    analyzer = ScamAnalyzer()
    res = await analyzer.analyze(AnalyzeRequest(text=text, sender=args.sender))

    if args.json:
        print(json.dumps(res.model_dump(mode="json"), indent=2))
        return

    colour = BAR.get(res.action, "")
    filled = round(res.risk_score / 5)
    print(f"\n  {colour} {res.risk_score:>3}/100 {RESET} "
          f"{'█' * filled}{DIM}{'░' * (20 - filled)}{RESET}  "
          f"{BOLD}{res.action.upper().replace('_', ' ')}{RESET}")
    print(f"  {BOLD}{res.headline}{RESET}")
    if res.likely_goal:
        print(f"  {DIM}Likely goal: {res.likely_goal}{RESET}")

    if res.factors:
        print(f"\n  {BOLD}What I noticed{RESET}")
        dot = {"critical": "\033[31m●", "high": "\033[31m●",
               "medium": "\033[33m●", "low": "\033[90m●"}
        for f in res.factors:
            print(f"   {dot.get(f.severity.value, '●')}{RESET} {f.label} "
                  f"{DIM}(+{f.contribution}){RESET}")
            print(f"     {DIM}\"{f.evidence[:70]}\"{RESET}")
            print(f"     {f.explanation}")

    if res.links:
        print(f"\n  {BOLD}Links{RESET}")
        for l in res.links:
            print(f"   [{l.verdict}] {l.url}")
            for r in l.reasons:
                print(f"     {DIM}- {r}{RESET}")

    if res.tone:
        t = res.tone
        print(f"\n  {BOLD}Tone{RESET}  pressure {t.pressure}  fear {t.fear}  "
              f"greed {t.greed}  authority {t.authority}")
        print(f"   {DIM}{t.summary}{RESET}")

    print(f"\n  → {res.recommended_action}")
    print(f"  {DIM}{res.analysis_ms}ms · via {res.analyzed_by}"
          f"{' · DEGRADED' if res.degraded else ''}{RESET}\n")


if __name__ == "__main__":
    asyncio.run(main())
