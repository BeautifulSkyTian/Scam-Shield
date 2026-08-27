# How to test the analyzer yourself

All commands run from `backend/`. Set up once:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

Your Gemini key is already in `.env`.

---

## 1. Type a message and see the analysis

```bash
.venv/bin/python -m tools.demo "your message here"
```

Real example:

```bash
.venv/bin/python -m tools.demo "URGENT: Your account will be closed in 24 hours. Confirm your password at http://chase-verify.tk"
```

You get a risk bar, the action, every signal with the quote that triggered it and how many
points it added, the link verdicts, the tone breakdown, and the latency.

Other forms:

```bash
# pipe from stdin (handy for long messages / pasting emails)
pbpaste | .venv/bin/python -m tools.demo

# pretend it came from a specific sender
.venv/bin/python -m tools.demo --sender "security@chase-alerts.tk" "Verify your account now"

# raw JSON -- exactly what the Chrome extension will receive
.venv/bin/python -m tools.demo --json "Send me 5 Apple gift cards"
```

**Try a legitimate message too.** That's the harder test:

```bash
.venv/bin/python -m tools.demo "Hey, running 10 min late, order without me"
.venv/bin/python -m tools.demo "Your verification code is 481920. Do not share this code with anyone."
```

Both should come back `0/100 ALLOW`. The second one is the interesting case — it mentions a
verification code, which sounds scammy, but nobody is *asking* you for it.

---

## 2. Run the whole test set at once

```bash
.venv/bin/python -m evals.run_eval          # scorecard over 20 cases
.venv/bin/python -m evals.run_eval -v       # + every signal and evidence quote
.venv/bin/python -m evals.run_eval --scams  # the 10 scams only
.venv/bin/python -m evals.run_eval --legit  # the 10 legitimate ones only
```

Takes ~1-2 minutes because it paces itself against the free-tier rate limit.

Add your own cases to `evals/dataset.py` — that's the right place to put any message that
surprises you. If the extension mis-handles something during the demo, add it there and it
becomes a permanent regression test.

---

## 3. Verify link checking on its own

Link checking is separate from the AI and can be tested with no key and no network:

```bash
.venv/bin/python -m tools.check_links
```

That runs 16 known URLs — 10 that must be flagged, 6 that must not — and prints the verdict,
the reasons, and the signals each one contributes. It is fully deterministic, so it is a real
pass/fail check, and it is how the two homoglyph/verdict bugs in `links.py` were found.

Check your own URLs:

```bash
.venv/bin/python -m tools.check_links http://paypa1.com/login
.venv/bin/python -m tools.check_links --anchor "paypal.com" http://evil-site.xyz/go
```

The `--anchor` form is the important one: it simulates a link whose visible text disagrees
with its destination, which is the strongest signal the system has.

### What is actually being checked

Without a Safe Browsing key, these run locally — no network:

| Check | Example caught |
|---|---|
| Anchor text vs destination | text says `paypal.com`, href goes to `paypa1-resolution.xyz` |
| Typo-squat / homoglyph | `paypa1.com`, `arnazon.com` (`rn` reads as `m`) |
| Brand in a subdomain | `paypal.com.secure-verify.ru` |
| Punycode homograph | `xn--pypal-4ve.com` |
| Raw IP host | `http://192.168.44.19/wallet-recovery` |
| `@` obfuscation | `http://paypal.com@evil.net/login` |
| URL shorteners | `bit.ly/...` hides the destination |
| High-abuse TLDs | `.tk`, `.top`, `.xyz`, `.zip` |
| Deep subdomain chains | `a.b.c.d.e.example.top` |

### Adding Google Safe Browsing (optional)

The heuristics above catch structural tricks. Safe Browsing adds *reputation* — URLs already
known to be malicious. It is free:

1. console.cloud.google.com → create/select a project
2. Enable **Safe Browsing API**
3. Create an API key
4. Put it in `backend/.env` as `SAFE_BROWSING_API_KEY=...`

Then:

```bash
.venv/bin/python -m tools.check_links --safe-browsing http://malware.testing.google.test/testing/malware/
```

That URL is Google's official test entry and should come back `malicious` with
`checked_by: ["heuristics", "safe_browsing"]`. If the key is missing or the API errors, the
lookup **fails open** — heuristics still apply and nothing crashes.

> Note: everything in the table above is verified. The Safe Browsing integration is written
> and unit-tested against mocked responses, but has **not** been run against the live Google
> API, because no key was available. Test it with the URL above once you add a key.

---

## 4. Offline tests (no API key, no network, instant)

```bash
.venv/bin/python -m pytest tests/ -q          # 89 tests
.venv/bin/python -m pytest tests/ -v          # see what each one checks
```

These cover the scoring maths, link heuristics, prefilter safety, rate limiter, and every
Gemini failure mode. Run these constantly; run the eval when you change the prompt.

---

## 5. Test it as an HTTP API (what the extension will actually hit)

```bash
.venv/bin/uvicorn app.main:app --reload --port 8000
```

Then:

```bash
curl -s localhost:8000/api/analyze -H 'Content-Type: application/json' -d '{"message":"Confirm your password now","links":[{"href":"http://paypa1.xyz","text":"paypal.com"}]}' | python3 -m json.tool
```

`curl localhost:8000/health` shows how much free-tier quota is left this minute.

---

## Changing the prompt

The prompt is in `app/analyzer/prompts.py`. To see it as the model does:

```bash
.venv/bin/python -c "from analyzer.prompts import SYSTEM_PROMPT; print(SYSTEM_PROMPT)"
```

**After any prompt edit, run the eval.** A prompt change that feels like an improvement and
measures like a regression is the most common way this kind of system gets worse, and the
scorecard is the only thing that will tell you.
