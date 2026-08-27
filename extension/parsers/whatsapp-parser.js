// parsers/whatsapp-parser.js
if (typeof window.WhatsAppParser === 'undefined' && typeof window.BaseMessageParser !== 'undefined') {
    window.WhatsAppParser = class WhatsAppParser extends window.BaseMessageParser {
        constructor() {
            super('WhatsApp');
        }

        extractMessageData(element) {
            // Target selectable text container inside WhatsApp message bubbles
            const textElement = element.querySelector('.selectable-text span, [data-testid="msg-container"] span') || element;
            const textContent = textElement?.innerText || textElement?.textContent || '';

            // Extract sender from parent metadata or fallback
            const copyableParent = element.closest('.copyable-text') || element;
            const preText = copyableParent?.dataset?.prePlainText || '';

            let sender = 'Unknown Sender';
            if (preText) {
                const parts = preText.split('] ');
                sender = parts.length > 1 ? parts[1].replace(':', '').trim() : preText;
            } else {
                sender = element.closest('[data-testid="msg-container"]') ? 'Contact' : 'Me';
            }

            // Extract links within message
            const links = Array.from(element.querySelectorAll('a')).map(a => a.href).filter(Boolean);

            // Message ID or fallback timestamp
            const messageId = copyableParent?.dataset?.id || `wa_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`;

            const payload = {
                id: messageId,
                platform: this.platformName,
                sender: sender,
                text: textContent.trim(),
                links: links,
                timestamp: new Date().toISOString()
            };

            if (payload.text.length > 0 && payload.text !== "tail-in" && payload.text !== "tail-out") {
                this.saveToArray(payload);
            }

            return payload;
        }
    };
}