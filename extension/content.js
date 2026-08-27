// content.js

// 1. Centralized Parser Registry
const PARSER_REGISTRY = [
    {
        domain: 'mail.google.com',
        className: 'GmailParser',
        selector: '.a3s'
    },
    {
        domain: 'web.whatsapp.com',
        className: 'WhatsAppParser',
        selector: '[data-testid="msg-container"], .message-in, .message-out'
    }
];

// Helper: Safely get the active parser and selector dynamically
function getActiveParserInfo() {
    const currentHost = window.location.hostname;
    const match = PARSER_REGISTRY.find(config => currentHost.includes(config.domain));

    if (match && typeof window[match.className] !== 'undefined') {
        return {
            instance: new window[match.className](),
            selector: match.selector
        };
    }

    return { instance: null, selector: null };
}

// Track processed nodes for MutationObserver
const processedElements = new WeakSet();

function processMessageElement(domElement) {
    const { instance: activeParser } = getActiveParserInfo();
    if (!activeParser || processedElements.has(domElement)) return;

    setTimeout(() => {
        try {
            const data = activeParser.extractMessageData(domElement);
            if (data && data.text) {
                processedElements.add(domElement);
                console.log(`[${activeParser.platformName}] Auto-Processed:`, data);

                if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
                    chrome.runtime.sendMessage({
                        type: 'ANALYZE_MESSAGE',
                        payload: data
                    });
                }
            }
        } catch (err) {
            console.warn('[Content Script] Auto-process error:', err);
        }
    }, 150);
}

// Observe dynamic DOM changes
const observer = new MutationObserver((mutations) => {
    const { selector: targetSelector } = getActiveParserInfo();
    if (!targetSelector) return;

    for (const mutation of mutations) {
        mutation.addedNodes.forEach((node) => {
            if (node.nodeType !== Node.ELEMENT_NODE) return;

            if (node.matches && node.matches(targetSelector)) {
                processMessageElement(node);
            } else {
                const targets = node.querySelectorAll?.(targetSelector);
                targets?.forEach(target => processMessageElement(target));
            }
        });
    }
});

// Start observer
const { selector: initialSelector } = getActiveParserInfo();
if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
    if (initialSelector) {
        document.querySelectorAll(initialSelector).forEach(el => processMessageElement(el));
    }
}

// Track right-clicked elements
let lastRightClickedElement = null;

document.addEventListener('contextmenu', (event) => {
    lastRightClickedElement = event.target;
}, true);

// Listen for background commands
if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        const { instance: activeParser, selector: targetSelector } = getActiveParserInfo();

        if (!activeParser || !targetSelector) {
            sendResponse({ status: 'error', reason: 'No active parser found on this host.' });
            return true;
        }

        // --- 1. SINGLE MESSAGE / HIGHLIGHTED SELECTION HANDLER ---
        if (request.action === 'ANALYZE_CLICKED_ELEMENT') {
            const selectedText = window.getSelection()?.toString().trim();

            if (selectedText && selectedText.length > 0) {
                sendResponse({
                    status: 'success',
                    payload: {
                        id: `selection_${Date.now()}`,
                        platform: activeParser.platformName,
                        sender: "User Highlight",
                        text: selectedText,
                        links: [],
                        timestamp: new Date().toISOString()
                    }
                });
                return true;
            }

            const clicked = lastRightClickedElement;
            const targetNode = clicked?.closest(targetSelector)
                || clicked?.closest('.gs, .ii, .nH')
                || document.querySelector(targetSelector);

            if (targetNode) {
                try {
                    const data = activeParser.extractMessageData(targetNode);
                    sendResponse({ status: 'success', payload: data });
                } catch (err) {
                    console.error('[Content Script] Error extracting message:', err);
                    sendResponse({ status: 'error', reason: err.message });
                }
            } else {
                sendResponse({ status: 'error', reason: 'Could not locate target message node.' });
            }
            return true;
        }

        // --- 2. BATCH / ALL MESSAGES HANDLER ---
        if (request.action === 'ANALYZE_ALL_MESSAGES') {
            // If WhatsApp runs inside multiple frames, only extract from the top-level window
            if (window !== window.top && window.location.hostname.includes('whatsapp')) {
                return false;
            }

            const elements = document.querySelectorAll(targetSelector);
            const allExtractedData = [];

            elements.forEach((el) => {
                try {
                    const data = activeParser.extractMessageData(el);
                    if (data && data.text) {
                        allExtractedData.push(data);
                    }
                } catch (err) {
                    console.warn('[Content Script] Skipped node:', err);
                }
            });

            console.log(`[Content Script] Extracted ${allExtractedData.length} total messages from DOM.`);

            sendResponse({
                status: 'success',
                payload: allExtractedData
            });
            return true;
        }

        return true;
    });
}