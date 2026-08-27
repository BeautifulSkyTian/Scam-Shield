// background.js

function sendToBackend(payloadArray) {
    console.log("Sending payload to backend:", JSON.stringify(payloadArray, null, 2));
}

chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.removeAll(() => {
        chrome.contextMenus.create({
            id: "analyze_selected_text",
            title: "Analyze Selected Text",
            contexts: ["selection"]
        });

        chrome.contextMenus.create({
            id: "analyze_scam_message",
            title: "Analyze Current Message",
            contexts: ["page"]
        });

        chrome.contextMenus.create({
            id: "analyze_all_messages",
            title: "Analyze All Visible Messages",
            contexts: ["page"]
        });
    });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (!tab?.id) return;

    // 1. Highlighted Text Analysis
    if (info.menuItemId === "analyze_selected_text" && info.selectionText) {
        const payload = [{
            id: `selection_${Date.now()}`,
            platform: "Selection",
            sender: "User Highlight",
            text: info.selectionText.trim(),
            links: [],
            timestamp: new Date().toISOString()
        }];

        console.log("=== [BACKGROUND] Selected Text Payload ===");
        sendToBackend(payload);
        return;
    }

    // 2. Single Message Analysis
    if (info.menuItemId === "analyze_scam_message") {
        chrome.tabs.sendMessage(tab.id, { action: "ANALYZE_CLICKED_ELEMENT" }, (response) => {
            if (chrome.runtime.lastError) {
                console.error("Communication error:", chrome.runtime.lastError.message);
                return;
            }
            if (response && response.status === 'success') {
                console.log("=== [BACKGROUND] Single Message Payload ===");
                sendToBackend([response.payload]);
            } else {
                console.warn("Single message analysis failed:", response?.reason);
            }
        });
        return;
    }

    // 3. All Visible Messages Analysis
    if (info.menuItemId === "analyze_all_messages") {
        chrome.tabs.sendMessage(tab.id, { action: "ANALYZE_ALL_MESSAGES" }, (response) => {
            if (chrome.runtime.lastError) {
                console.error("Communication error:", chrome.runtime.lastError.message);
                return;
            }
            if (response && response.status === 'success') {
                console.log(`=== [BACKGROUND] Batch Payload (${response.payload.length} messages) ===`);
                sendToBackend(response.payload);
            } else {
                console.warn("Batch analysis failed:", response?.reason);
            }
        });
        return;
    }
});