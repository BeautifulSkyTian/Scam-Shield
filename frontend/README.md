# Scam Shield Frontend

React side-panel frontend for the Scam Shield Chrome extension.

No API keys belong in this directory. The extension communicates with the backend, which owns all provider credentials. `.env`, local environment variants, private-key files, build output, dependencies, and macOS metadata are ignored by Git.

## Development preview

```bash
npm install
npm run dev
```

Open `http://127.0.0.1:5173`.

Development requests use the Vite proxy and are forwarded to `http://127.0.0.1:8000`. This avoids local CORS differences between `localhost` and `127.0.0.1`.

To use another backend, copy `.env.example` to `.env` and set `VITE_API_URL` to its full address.

## Build the extension

```bash
npm run build
```

Then open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**, and select the generated `frontend/dist` directory.

The extension has two modes:

- **Basic mode:** highlight message text on a normal webpage, select the Scam Shield toolbar icon, and choose **Check highlighted text**. The popup shows a quick score, risk level, headline, and recommended action.
- **Advanced mode:** choose the **Advanced** tab, **Open full analyzer**, or **View advanced details** to open the full side panel with evidence, link checks, manipulation analysis, metadata, history, and manual message entry.

Use the mode switch at the top of either view to move between Basic and Advanced. Returning to Basic closes the side panel and opens the toolbar popup. This requires Chrome 141 or newer.

After installing or reloading the extension, refresh the webpage before using highlighted-text analysis so the content script is available.

## Backend

Start the FastAPI service from the repository's `backend` directory:

```bash
uvicorn app.main:app --reload
```

The frontend uses:

- `POST /api/analyze`
- `GET /api/history`

Extension requests pass through `public/background.js`. This lets the extension reach the local API without changing the backend CORS configuration.

## Page integration

`public/content-ui.js` provides the interface for the message-extraction content script:

```js
const result = await window.ScamShieldFrontend.analyzeAndRender(
  messageElement,
  {
    message: messageText,
    sender,
    url,
    platform: location.hostname,
    page_url: location.href,
    message_id: messageId
  }
);
```

It can also render a result that was already analyzed:

```js
window.ScamShieldFrontend.renderAnalysis(messageElement, result);
```

The renderer follows the backend's `action` field. `allow` makes no page changes, `notice` adds a subtle badge, `warn` adds a warning highlight, `strong_warn` adds a prominent warning, and `block` adds a protective blurred cover with options to view the analysis or reveal the message.
