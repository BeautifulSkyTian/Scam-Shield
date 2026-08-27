// parsers/gmail-parser.js
if (typeof window.GmailParser === 'undefined' && typeof window.BaseMessageParser !== 'undefined') {
    window.GmailParser = class GmailParser extends window.BaseMessageParser {
        constructor() {
            super('Gmail');
        }

        extractMessageData(element) {
            if (!element) return null;

            // 1. Locate the parent email message container (.gs is Gmail's individual message card)
            const messageCard = element.closest('.gs, .ii') || element.closest('[role="main"]') || element;

            // 2. Find the actual message body element inside that card
            // Gmail puts email body text inside .a3s or .ii.gt
            const bodyNode = messageCard.querySelector('.a3s') || messageCard.querySelector('.ii.gt') || element;

            // 3. Extract text from the body node, ignoring top header text if body is found
            const textContent = bodyNode.innerText || bodyNode.textContent || '';

            // 4. Extract sender details
            const senderElement = messageCard.querySelector('.gD') || document.querySelector('.gD');
            const sender = senderElement ? (senderElement.getAttribute('email') || senderElement.innerText) : 'Unknown Sender';

            // 5. Extract links inside the email body
            const links = Array.from(bodyNode.querySelectorAll('a')).map(a => a.href).filter(Boolean);

            // 6. Message ID
            const messageId = bodyNode.getAttribute('data-message-id') || messageCard.getAttribute('data-legacy-message-id') || `gmail_${Date.now()}`;

            const payload = {
                id: messageId,
                platform: this.platformName,
                sender: sender,
                text: textContent.trim(),
                links: links,
                timestamp: new Date().toISOString()
            };

            if (payload.text.length > 0) {
                this.saveToArray(payload);
            }

            return payload;
        }
    };
}