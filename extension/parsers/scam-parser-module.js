// parsers/scam-parser-module.js
if (typeof window.extractedMessageStore === 'undefined') {
  window.extractedMessageStore = [];
}

if (typeof window.BaseMessageParser === 'undefined') {
  window.BaseMessageParser = class BaseMessageParser {
    constructor(platformName) {
      if (new.target === BaseMessageParser) {
        throw new Error("BaseMessageParser cannot be instantiated directly.");
      }
      this.platformName = platformName;
    }

    extractMessageData(node) {
      throw new Error("extractMessageData() must be implemented.");
    }

    saveToArray(data) {
      const exists = window.extractedMessageStore.some(item => item.id === data.id);
      if (!exists) {
        window.extractedMessageStore.push(data);
      }
      return window.extractedMessageStore;
    }

    exportForAnalysis() {
      return JSON.parse(JSON.stringify(window.extractedMessageStore));
    }
  };
}