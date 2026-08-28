"""Prefilter safety.

The only failure that matters here is a scam being skipped. These tests are
the guard rail on that -- if someone trims the lexicon to save quota, this
suite is what tells them they just let a scam category through.
"""

import pytest

from app.analyzer.prefilter import needs_model
from evals.dataset import LEGITIMATE, SCAMS


@pytest.mark.parametrize("case", SCAMS, ids=lambda c: c.name)
def test_no_scam_is_ever_skipped(case):
    """Non-negotiable. A skipped scam reaches the user with no warning."""
    should_call, why = needs_model(case.text, case.links)
    assert should_call, f"{case.name} would skip the model ({why})"


def test_ordinary_chatter_is_skipped():
    assert not needs_model("hey, running 5 min late, grab me a coffee?")[0]
    assert not needs_model("Sounds good. See you Tuesday.")[0]


def test_any_link_forces_analysis():
    assert needs_model("check this out https://example.com")[0]
    assert needs_model("no url here", links=[object()])[0]


def test_long_messages_always_analysed():
    assert needs_model("blah blah. " * 100)[0]


@pytest.mark.parametrize("text", [
    "Please confirm your password",
    "Send me a gift card",
    "Your account has been suspended",
    "You are a WINNER! Claim your prize",
    "install AnyDesk so we can help",
    "keep this between us",
])
def test_risk_vocabulary_forces_analysis(text):
    assert needs_model(text)[0]


def test_lexicon_matching_is_case_insensitive():
    assert needs_model("URGENT")[0] and needs_model("urgent")[0]


def test_prefilter_saves_quota_on_the_legit_set():
    """Sanity check that the filter isn't so paranoid it never fires --
    if this hits 0 the filter is dead weight and quota is being burned."""
    skipped = sum(1 for c in LEGITIMATE if not needs_model(c.text, c.links)[0])
    assert skipped >= 2
