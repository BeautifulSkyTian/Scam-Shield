# Scam Shield Frontend

React side-panel frontend for the Scam Shield Chrome extension.

## Development preview

```bash
npm install
npm run dev
```

Open `http://localhost:5173`.

The frontend connects to `http://127.0.0.1:8000` by default. To use another backend URL, copy `.env.example` to `.env` and change `VITE_API_URL`.

## Build the extension

```bash
npm run build
```

Then open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**, and select the generated `frontend/dist` directory.

Select the Scam Shield toolbar icon on any normal webpage to open its popup, then choose **Open analyzer** to launch the full side panel.

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

The renderer keeps low-risk messages quiet, adds a light warning to suspicious messages, strongly outlines high-risk messages, and gives scores above 80 a protective blurred cover with options to view the analysis or reveal the message.
