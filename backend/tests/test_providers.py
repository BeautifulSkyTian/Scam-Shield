"""Provider layer -- response parsing and failure modes. No network."""

import pytest

from app.analyzer.providers import build_provider
from app.analyzer.providers.gemini import GeminiProvider
from app.analyzer.schema import ModelVerdict

VALID_JSON = """{
  "category": "phishing",
  "signals": [{"signal": "urgency", "severity": "high",
               "evidence": "within 24 hours", "explanation": "Fake deadline."}],
  "tone": {"valence": "negative", "pressure": 90, "fear": 80, "greed": 0,
           "authority": 60, "summary": "Deadline pressure."},
  "likely_goal": "Steal credentials",
  "confidence": "high"
}"""


def _envelope(text, finish="STOP", thought=False):
    return {"candidates": [{"finishReason": finish,
                            "content": {"parts": [{"text": text, "thought": thought}]}}]}


def test_parses_valid_response():
    v = GeminiProvider._parse(_envelope(VALID_JSON))
    assert isinstance(v, ModelVerdict)
    assert v.category.value == "phishing"
    assert v.signals[0].evidence == "within 24 hours"


def test_skips_thought_parts_and_takes_the_answer():
    """With thinking on, earlier parts can be thought summaries; the answer
    is the last non-thought part. Taking parts[0] would parse reasoning prose
    as JSON and fail every time."""
    data = {"candidates": [{"finishReason": "STOP", "content": {"parts": [
        {"text": "Let me consider the urgency...", "thought": True},
        {"text": VALID_JSON},
    ]}}]}
    v = GeminiProvider._parse(data)
    assert v is not None and v.category.value == "phishing"


@pytest.mark.parametrize("data,why", [
    ({"promptFeedback": {"blockReason": "SAFETY"}}, "input blocked"),
    ({"candidates": []}, "no candidates"),
    ({}, "empty response"),
    (_envelope(VALID_JSON, finish="SAFETY"), "safety finish"),
    (_envelope(VALID_JSON, finish="MAX_TOKENS"), "truncated"),
    (_envelope('{"category": "phishing"'), "invalid json"),
    (_envelope('{"category": "not_a_real_category", "signals": []}'), "schema violation"),
    (_envelope(VALID_JSON, thought=True), "only thought parts"),
])
def test_all_failure_modes_return_none_not_exception(data, why):
    """Every one of these must degrade, never raise -- a provider that throws
    takes down the whole request."""
    assert GeminiProvider._parse(data) is None, why


def test_payload_uses_json_schema_and_disables_safety():
    p = GeminiProvider(api_key="test-key")
    body = p._payload("SYSTEM", "USER")
    cfg = body["generationConfig"]
    assert cfg["responseMimeType"] == "application/json"
    assert "responseJsonSchema" in cfg      # not responseSchema -- needs $defs
    assert cfg["temperature"] == 0.0
    assert body["systemInstruction"]["parts"][0]["text"] == "SYSTEM"
    assert all(s["threshold"] == "BLOCK_NONE" for s in body["safetySettings"])


def test_schema_sent_to_gemini_has_defs():
    """Guards the responseSchema/responseJsonSchema distinction: if this ever
    flattens, someone has probably swapped the field name back."""
    body = GeminiProvider(api_key="k")._payload("s", "u")
    assert "$defs" in body["generationConfig"]["responseJsonSchema"]


def test_missing_key_fails_loudly_at_construction():
    """Fail at startup, not on the first user message."""
    with pytest.raises(ValueError, match="No Gemini API key"):
        GeminiProvider(api_key="")


def test_registry_rejects_unknown_provider():
    with pytest.raises(ValueError, match="Unknown provider"):
        build_provider("gpt4")


def test_registry_defaults_to_gemini():
    assert build_provider("gemini", api_key="k").name == "gemini"


def test_every_model_signal_has_a_severity_anchor():
    """The prompt is generated from the taxonomy. If someone adds a signal
    without an anchor, the prompt build crashes -- better here, loudly."""
    from app.analyzer.categories import LINK_OWNED_SIGNALS, SEVERITY_ANCHORS, Signal

    missing = [
        s.value for s in Signal
        if s not in LINK_OWNED_SIGNALS and s not in SEVERITY_ANCHORS
    ]
    assert not missing, f"signals without severity anchors: {missing}"


def test_prompt_lists_every_model_signal_and_no_link_signals():
    from app.analyzer.categories import LINK_OWNED_SIGNALS, Signal
    from app.analyzer.prompts import SYSTEM_PROMPT

    for s in Signal:
        if s in LINK_OWNED_SIGNALS:
            continue
        assert f"**{s.value}**" in SYSTEM_PROMPT, f"{s.value} missing from prompt"
