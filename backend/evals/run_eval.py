"""Run the analyzer over the golden set and print a scorecard.

    python -m evals.run_eval            # all cases
    python -m evals.run_eval --scams    # scams only
    python -m evals.run_eval -v         # show every signal

Decision threshold for pass/fail is `action != "allow"` (score >= 25), i.e.
"did the extension say anything at all". Bounds violations are reported
separately as calibration drift.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from dotenv import load_dotenv

load_dotenv()

from app.analyzer import AnalyzeRequest, LinkInput, ScamAnalyzer
from evals.dataset import ALL_CASES, LEGITIMATE, SCAMS, Case

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


async def run_case(analyzer: ScamAnalyzer, case: Case):
    req = AnalyzeRequest(
        text=case.text,
        sender=case.sender,
        links=[LinkInput(href=h, text=t) for h, t in case.links],
    )
    return case, await analyzer.analyze(req)


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scams", action="store_true")
    ap.add_argument("--legit", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--concurrency", type=int, default=4,
                    help="The provider rate-limits itself; this only bounds fan-out.")
    ap.add_argument("--no-prefilter", action="store_true",
                    help="Force an API call for every case (costs more quota).")
    args = ap.parse_args()

    cases = SCAMS if args.scams else LEGITIMATE if args.legit else ALL_CASES
    analyzer = ScamAnalyzer(use_prefilter=not args.no_prefilter)
    rpm = getattr(analyzer.provider, "rpm", None)
    print(f"\nprovider: {analyzer.provider.name} "
          f"({getattr(analyzer.provider, 'model', 'n/a')})"
          + (f"  |  {rpm} req/min free tier" if rpm else "")
          + f"  |  prefilter: {'off' if args.no_prefilter else 'on'}")
    if rpm and len(cases) > rpm:
        print(f"{DIM}{len(cases)} cases at {rpm} rpm -- expect roughly "
              f"{len(cases) / rpm:.0f} min. The limiter paces automatically.{RESET}")

    sem = asyncio.Semaphore(args.concurrency)

    async def guarded(c: Case):
        async with sem:
            return await run_case(analyzer, c)

    results = await asyncio.gather(*(guarded(c) for c in cases))

    tp = fp = tn = fn = prefiltered = 0
    drift: list[str] = []
    wrong_category: list[str] = []
    degraded = 0

    print(f"\n{'CASE':<26} {'SCORE':>6}  {'ACTION':<12} {'CATEGORY':<24} RESULT")
    print("-" * 92)

    for case, res in sorted(results, key=lambda r: -r[1].risk_score):
        flagged = res.action != "allow"
        if case.expect_scam:
            ok = flagged
            tp, fn = tp + ok, fn + (not ok)
        else:
            ok = not flagged
            tn, fp = tn + ok, fp + (not ok)

        if res.degraded:
            degraded += 1
        if res.analyzed_by == "prefilter":
            prefiltered += 1
        if res.risk_score < case.min_score:
            drift.append(f"{case.name}: {res.risk_score} < min {case.min_score}")
        if res.risk_score > case.max_score:
            drift.append(f"{case.name}: {res.risk_score} > max {case.max_score}")
        if case.categories and res.category not in case.categories:
            wrong_category.append(
                f"{case.name}: got {res.category.value}, "
                f"expected one of {[c.value for c in case.categories]}"
            )

        colour = GREEN if ok else RED
        mark = "PASS" if ok else ("FALSE NEG" if case.expect_scam else "FALSE POS")
        flag = {
            "link_check_only": f"{YELLOW}(model failed){RESET}",
            "prefilter": f"{DIM}(no API call){RESET}",
        }.get(res.analyzed_by, "")
        print(
            f"{case.name:<26} {res.risk_score:>6}  {res.action:<12} "
            f"{res.category.value:<24} {colour}{mark}{RESET} {flag}"
        )
        if args.verbose:
            print(f"    {DIM}{res.headline}{RESET}")
            for f in res.factors:
                print(f"    {DIM}  +{f.contribution:>2}  {f.label} ({f.severity.value}) "
                      f"— \"{f.evidence[:60]}\"{RESET}")
            for l in res.links:
                print(f"    {DIM}  link {l.verdict}: {l.url} {l.reasons}{RESET}")
            print()

    total = len(results)
    recall = tp / (tp + fn) if tp + fn else 1.0
    precision = tp / (tp + fp) if tp + fp else 1.0

    print("-" * 92)
    print(f"  scams caught      {tp}/{tp + fn}   (recall    {recall:.0%})")
    print(f"  legit left alone  {tn}/{tn + fp}   (precision {precision:.0%})")
    print(f"  overall           {tp + tn}/{total}")
    print(f"  API calls saved   {prefiltered}/{total} by prefilter")
    if degraded:
        print(f"  {YELLOW}{degraded} case(s) degraded — the model call failed. "
              f"Results below are NOT a real measure of the model.{RESET}")

    if drift:
        print(f"\n{YELLOW}Calibration drift ({len(drift)}):{RESET}")
        for d in drift:
            print(f"  - {d}")
    if wrong_category:
        print(f"\n{YELLOW}Category mismatches ({len(wrong_category)}):{RESET}")
        for w in wrong_category:
            print(f"  - {w}")

    return 0 if (fp + fn) == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
