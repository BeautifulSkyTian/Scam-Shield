const loadingState = document.getElementById("loading-state");
const emptyState = document.getElementById("empty-state");
const selectionState = document.getElementById("selection-state");
const resultState = document.getElementById("result-state");
const selectionPreview = document.getElementById("selection-preview");
const analyzeButton = document.getElementById("analyze-selection");
const advancedButton = document.getElementById("open-advanced");
const advancedModeTab = document.getElementById("advanced-mode-tab");
const detailsButton = document.getElementById("view-details");
const errorMessage = document.getElementById("popup-error");
const IS_EXTENSION = Boolean(globalThis.chrome?.runtime?.id);

let activeTabId;
let selectedMessage;
let analysisResult;

loadSelection();

async function loadSelection() {
  if (!IS_EXTENSION) {
    loadingState.hidden = true;
    showEmpty(
      "Basic mode preview",
      "Load the dist folder in Chrome to read highlighted messages from a webpage."
    );
    return;
  }

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    activeTabId = tab?.id;

    if (!activeTabId) throw new Error("Open a normal website to use Scam Shield.");

    const response = await requestSelection(activeTabId);

    selectedMessage = response?.selection;
    loadingState.hidden = true;

    if (!selectedMessage?.message) {
      showEmpty(
        "Highlight a message",
        "Select suspicious text on the page, then reopen Scam Shield for a quick check."
      );
      return;
    }

    selectionPreview.textContent = selectedMessage.message;
    selectionState.hidden = false;
  } catch (error) {
    loadingState.hidden = true;
    showEmpty("This page cannot be read", error.message);
  }
}

async function requestSelection(tabId) {
  let response;

  try {
    response = await chrome.tabs.sendMessage(tabId, {
      type: "SCAM_SHIELD_GET_SELECTION"
    });
  } catch {
    response = null;
  }

  if (response?.ok) return response;

  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["content-ui.js"]
    });

    return await chrome.tabs.sendMessage(tabId, {
      type: "SCAM_SHIELD_GET_SELECTION"
    });
  } catch {
    throw new Error("Open a normal website, refresh it, and highlight the message again.");
  }
}

analyzeButton.addEventListener("click", async () => {
  setError("");
  analyzeButton.disabled = true;
  analyzeButton.textContent = "Checking...";

  try {
    const response = await chrome.runtime.sendMessage({
      type: "SCAM_SHIELD_API_REQUEST",
      path: "/api/analyze",
      method: "POST",
      body: selectedMessage
    });

    if (!response?.ok) throw new Error(response?.error || "Analysis failed.");

    analysisResult = response.result;
    showResult(analysisResult);
  } catch (error) {
    setError(error.message);
    analyzeButton.disabled = false;
    analyzeButton.textContent = "Check highlighted text";
  }
});

detailsButton.addEventListener("click", () => openAdvanced(analysisResult));
advancedButton.addEventListener("click", () => openAdvanced());
advancedModeTab.addEventListener("click", () => openAdvanced());

async function openAdvanced(result) {
  setError("");

  if (!IS_EXTENSION) {
    window.location.href = "/";
    return;
  }

  try {
    if (!activeTabId) throw new Error("Open a normal website before launching Advanced mode.");

    if (result) {
      await chrome.runtime.sendMessage({
        type: "SCAM_SHIELD_OPEN_RESULT",
        result,
        tabId: activeTabId
      });
    } else {
      await chrome.sidePanel.open({ tabId: activeTabId });
    }

    window.close();
  } catch (error) {
    setError(error.message);
  }
}

function showEmpty(heading, message) {
  document.getElementById("empty-heading").textContent = heading;
  document.getElementById("empty-message").textContent = message;
  emptyState.hidden = false;
}

function showResult(result) {
  const tone = toneFor(result);
  selectionState.hidden = true;
  emptyState.hidden = true;
  resultState.hidden = false;
  resultState.dataset.tone = tone.key;
  document.getElementById("quick-score").textContent = result.risk_score;
  document.getElementById("risk-label").textContent = tone.label;
  document.getElementById("result-category").textContent = result.category;
  document.getElementById("result-headline").textContent = result.headline || result.summary;
  document.getElementById("result-action").textContent = result.recommended_action;
}

function toneFor(result) {
  const tones = {
    allow: { key: "safe", label: "Safe" },
    notice: { key: "low", label: "Low risk" },
    warn: { key: "medium", label: "Suspicious" },
    strong_warn: { key: "high", label: "High risk" },
    block: { key: "critical", label: "Critical risk" }
  };

  return tones[result.action] || { key: "medium", label: result.risk_level || "Analyzed" };
}

function setError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = !message;
}
