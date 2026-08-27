const riskTones = {
  low: { label: "Low risk", color: "#158464", background: "#e9f6f1" },
  suspicious: { label: "Suspicious", color: "#a86005", background: "#fff4df" },
  high: { label: "High risk", color: "#c74429", background: "#fff0eb" },
  extreme: { label: "Extremely high risk", color: "#b51f37", background: "#fdecef" }
};

function getRiskTone(score) {
  if (score <= 20) return "low";
  if (score <= 60) return "suspicious";
  if (score <= 80) return "high";
  return "extreme";
}

async function analyzeMessage(payload) {
  const response = await chrome.runtime.sendMessage({
    type: "SCAM_SHIELD_API_REQUEST",
    path: "/api/analyze",
    method: "POST",
    body: payload
  });

  if (!response?.ok) throw new Error(response?.error || "Analysis failed.");
  return response.result;
}

function renderAnalysis(element, result) {
  if (!(element instanceof HTMLElement)) return null;

  element.querySelector(":scope > scam-shield-warning")?.remove();

  const toneKey = getRiskTone(result.risk_score);
  const tone = riskTones[toneKey];
  const originalPosition = getComputedStyle(element).position;

  if (originalPosition === "static") element.style.position = "relative";

  const outlineWidth = toneKey === "low" ? 0 : toneKey === "suspicious" ? 1 : 3;
  element.style.outline = outlineWidth ? `${outlineWidth}px solid ${tone.color}` : "none";
  element.style.outlineOffset = outlineWidth ? "3px" : "0";
  element.dataset.scamShieldRisk = toneKey;

  const warning = document.createElement("scam-shield-warning");
  const shadow = warning.attachShadow({ mode: "open" });
  warning.style.position = "absolute";
  warning.style.inset = toneKey === "extreme" ? "-3px" : "8px 8px auto auto";
  warning.style.zIndex = "2147483646";
  warning.style.pointerEvents = "none";

  shadow.innerHTML = toneKey === "extreme"
    ? createExtremeWarning(result, tone)
    : createBadge(result, tone);

  const openButton = shadow.querySelector("[data-open-analysis]");
  openButton.addEventListener("click", () => {
    chrome.runtime.sendMessage({
      type: "SCAM_SHIELD_OPEN_RESULT",
      result
    });
  });

  shadow.querySelector("[data-reveal]")?.addEventListener("click", () => {
    warning.style.inset = "8px 8px auto auto";
    shadow.innerHTML = createBadge(result, tone);
    shadow.querySelector("[data-open-analysis]").addEventListener("click", () => {
      chrome.runtime.sendMessage({
        type: "SCAM_SHIELD_OPEN_RESULT",
        result
      });
    });
  });

  element.appendChild(warning);
  return warning;
}

async function analyzeAndRender(element, payload) {
  const result = await analyzeMessage(payload);
  renderAnalysis(element, result);
  return result;
}

function createBadge(result, tone) {
  return `
    <style>
      button { display: inline-flex; align-items: center; gap: 6px; border: 1px solid color-mix(in srgb, ${tone.color} 28%, transparent); border-radius: 999px; padding: 6px 10px; color: ${tone.color}; background: ${tone.background}; box-shadow: 0 5px 16px rgba(28, 38, 34, .16); cursor: pointer; pointer-events: auto; font: 800 11px/1 system-ui, sans-serif; }
      svg { width: 13px; height: 13px; fill: currentColor; }
    </style>
    <button type="button" data-open-analysis title="Open Scam Shield analysis">
      ${shieldIcon()}
      <span>${result.risk_score} · ${tone.label}</span>
    </button>`;
}

function createExtremeWarning(result, tone) {
  return `
    <style>
      .cover { position: absolute; inset: 0; display: grid; place-items: center; border: 2px solid ${tone.color}; border-radius: 8px; background: rgba(253, 236, 239, .82); backdrop-filter: blur(7px); pointer-events: auto; font-family: system-ui, sans-serif; }
      .content { max-width: 260px; padding: 18px; text-align: center; }
      svg { width: 25px; height: 25px; fill: ${tone.color}; }
      strong { display: block; margin: 7px 0 4px; color: ${tone.color}; font-size: 14px; }
      p { margin: 0 0 11px; color: #71343f; font-size: 11px; line-height: 1.4; }
      .actions { display: flex; justify-content: center; gap: 7px; }
      button { border: 0; border-radius: 8px; padding: 7px 10px; cursor: pointer; font: 700 10px system-ui, sans-serif; }
      [data-open-analysis] { color: white; background: ${tone.color}; }
      [data-reveal] { color: #71343f; background: white; }
    </style>
    <div class="cover">
      <div class="content">
        ${shieldIcon()}
        <strong>Extremely high risk</strong>
        <p>Scam Shield hid this message because it may be dangerous.</p>
        <div class="actions">
          <button type="button" data-open-analysis>View analysis</button>
          <button type="button" data-reveal>Reveal message</button>
        </div>
      </div>
    </div>`;
}

function shieldIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4.5 5v5.4c0 5 3.2 9.6 7.5 11.1 4.3-1.5 7.5-6.1 7.5-11.1V5L12 2Zm0 3.1 4.7 1.9v3.4c0 3.4-1.9 6.8-4.7 8.1-2.8-1.3-4.7-4.7-4.7-8.1V7L12 5.1Z"/></svg>`;
}

window.ScamShieldFrontend = {
  analyzeMessage,
  renderAnalysis,
  analyzeAndRender
};
