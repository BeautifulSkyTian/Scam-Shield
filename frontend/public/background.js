const API_URL = "http://127.0.0.1:8000";

chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
});

chrome.runtime.onStartup.addListener(() => {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCAM_SHIELD_API_REQUEST") {
    requestBackend(message)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));

    return true;
  }

  if (message.type === "SCAM_SHIELD_OPEN_RESULT") {
    openResult(message.result, sender)
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));

    return true;
  }
});

async function requestBackend(message) {
  const options = {
    method: message.method || "GET",
    headers: { "Content-Type": "application/json" }
  };

  if (message.body) options.body = JSON.stringify(message.body);

  let response;

  try {
    response = await fetch(`${API_URL}${message.path}`, options);
  } catch {
    throw new Error(`Cannot reach the backend at ${API_URL}. Make sure FastAPI is running.`);
  }

  if (!response.ok) {
    let errorMessage = "Scam Shield could not complete the request.";

    try {
      const body = await response.json();
      errorMessage = body.detail || errorMessage;
    } catch {
      errorMessage = "The backend returned an unexpected response.";
    }

    throw new Error(errorMessage);
  }

  return response.json();
}

async function openResult(result, sender) {
  const panelRequest = sender.tab?.id
    ? chrome.sidePanel.open({ tabId: sender.tab.id })
    : Promise.resolve();

  await chrome.storage.session.set({ selectedAnalysis: result });
  await panelRequest;
}
