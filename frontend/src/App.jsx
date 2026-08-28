import { useCallback, useEffect, useState } from "react";

const API_URL = (
  import.meta.env.VITE_API_URL ||
  (import.meta.env.DEV ? "" : "http://127.0.0.1:8000")
).replace(/\/$/, "");
const BACKEND_NAME = API_URL || "http://127.0.0.1:8000";
const IS_EXTENSION = Boolean(globalThis.chrome?.runtime?.id);

const initialForm = {
  message: "",
  sender: "",
  platform: "web",
  pageUrl: "",
  links: [{ href: "", text: "" }]
};

function ShieldIcon({ size = 24 }) {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      width={size}
      height={size}
    >
      <path d="M12 2 4.5 5v5.4c0 5 3.2 9.6 7.5 11.1 4.3-1.5 7.5-6.1 7.5-11.1V5L12 2Zm0 3.1 4.7 1.9v3.4c0 3.4-1.9 6.8-4.7 8.1-2.8-1.3-4.7-4.7-4.7-8.1V7L12 5.1Z" />
    </svg>
  );
}

function getRiskTone(score, action) {
  const tones = {
    allow: { key: "safe", label: "Safe" },
    notice: { key: "low", label: "Low risk" },
    warn: { key: "medium", label: "Suspicious" },
    strong_warn: { key: "high", label: "High risk" },
    block: { key: "critical", label: "Critical risk" }
  };

  if (tones[action]) return tones[action];
  if (score <= 24) return tones.allow;
  if (score <= 44) return tones.notice;
  if (score <= 69) return tones.warn;
  if (score <= 87) return tones.strong_warn;
  return tones.block;
}

async function request(path, options) {
  const extensionApi = globalThis.chrome;

  if (extensionApi?.runtime?.id) {
    const response = await extensionApi.runtime.sendMessage({
      type: "SCAM_SHIELD_API_REQUEST",
      path,
      method: options?.method || "GET",
      body: options?.body ? JSON.parse(options.body) : null
    });

    if (!response?.ok) throw new Error(response?.error || "The extension request failed.");
    return response.result;
  }

  let response;

  try {
    response = await fetch(`${API_URL}${path}`, options);
  } catch {
    throw new Error(`Cannot reach the backend at ${BACKEND_NAME}. Make sure FastAPI is running.`);
  }

  if (!response.ok) {
    let message = "Scam Shield could not complete the request.";

    try {
      const body = await response.json();
      message = body.detail || message;
    } catch {
      message = "The backend returned an unexpected response.";
    }

    throw new Error(message);
  }

  return response.json();
}

function AnalyzerForm({ form, setForm, onSubmit, loading }) {
  function updateField(event) {
    setForm((current) => ({
      ...current,
      [event.target.name]: event.target.value
    }));
  }

  function updateLink(index, field, value) {
    setForm((current) => ({
      ...current,
      links: current.links.map((link, linkIndex) =>
        linkIndex === index ? { ...link, [field]: value } : link
      )
    }));
  }

  function addLink() {
    setForm((current) => ({
      ...current,
      links: [...current.links, { href: "", text: "" }]
    }));
  }

  function removeLink(index) {
    setForm((current) => ({
      ...current,
      links: current.links.filter((_, linkIndex) => linkIndex !== index)
    }));
  }

  return (
    <section className="analyzer-card">
      <div className="section-heading">
        <span className="eyebrow">CHECK A MESSAGE</span>
        <h1>Does something feel off?</h1>
        <p>
          Paste a suspicious message. The Guard will check for pressure,
          impersonation, unsafe links, and other warning signs.
        </p>
      </div>

      <form onSubmit={onSubmit}>
        <label className="message-field">
          Message
          <textarea
            name="message"
            value={form.message}
            onChange={updateField}
            rows="8"
            placeholder="Paste a suspicious text, email, or direct message here..."
            required
          />
        </label>

        <div className="field-row">
          <label>
            Sender <span>optional</span>
            <input
              name="sender"
              value={form.sender}
              onChange={updateField}
              type="text"
              placeholder="e.g. My Bank or alerts@example.com"
            />
          </label>
          <label>
            Message source <span>optional</span>
            <select name="platform" value={form.platform} onChange={updateField}>
              <option value="web">Website</option>
              <option value="email">Email</option>
              <option value="sms">Text message</option>
              <option value="social">Social media</option>
              <option value="marketplace">Marketplace</option>
              <option value="other">Other</option>
            </select>
          </label>
        </div>

        <details className="context-fields">
          <summary>
            Add links and page context <span>optional, improves accuracy</span>
          </summary>

          <label>
            Page where you saw it <span>optional</span>
            <input
              name="pageUrl"
              value={form.pageUrl}
              onChange={updateField}
              type="url"
              placeholder="https://example.com/inbox"
            />
          </label>

          <div className="link-editor">
            <div className="link-editor-heading">
              <div>
                <strong>Links in the message</strong>
                <span>Add the visible label too when it differs from the destination.</span>
              </div>
              <button type="button" onClick={addLink}>+ Add link</button>
            </div>

            {form.links.map((link, index) => (
              <div className="link-input-row" key={index}>
                <label>
                  Destination
                  <input
                    type="url"
                    value={link.href}
                    onChange={(event) => updateLink(index, "href", event.target.value)}
                    placeholder="https://example.com"
                  />
                </label>
                <label>
                  Displayed text <span>optional</span>
                  <input
                    type="text"
                    value={link.text}
                    onChange={(event) => updateLink(index, "text", event.target.value)}
                    placeholder="e.g. paypal.com"
                  />
                </label>
                {form.links.length > 1 && (
                  <button
                    className="remove-link"
                    type="button"
                    onClick={() => removeLink(index)}
                    aria-label={`Remove link ${index + 1}`}
                  >
                    ×
                  </button>
                )}
              </div>
            ))}
          </div>
        </details>

        <button className="primary-button" type="submit" disabled={loading}>
          {loading ? <span className="button-spinner" /> : <ShieldIcon size={19} />}
          {loading ? "Inspecting message..." : "Analyze message"}
        </button>
      </form>
    </section>
  );
}

function ResultCard({ result, onReset }) {
  const tone = getRiskTone(result.risk_score, result.action);
  const manipulation = result.tone
    ? [
        ["Pressure", result.tone.pressure],
        ["Fear", result.tone.fear],
        ["Greed", result.tone.greed],
        ["Authority", result.tone.authority]
      ]
    : [];

  return (
    <section className={`result-card tone-${tone.key}`}>
      <div className="result-header">
        <div
          className="score-ring"
          style={{ "--score": `${result.risk_score * 3.6}deg` }}
        >
          <div>
            <strong>{result.risk_score}</strong>
            <span>/100</span>
          </div>
        </div>

        <div className="risk-copy">
          <span className="eyebrow">RISK ASSESSMENT</span>
          <h2>{tone.label}</h2>
          <span className="category-pill">{result.category}</span>
        </div>
      </div>

      <div className="summary-box">
        <span className="eyebrow">THE GUARD SAYS</span>
        <p>{result.headline || result.summary}</p>
      </div>

      {(result.confidence || result.analyzed_by || result.analysis_ms != null) && (
        <div className="analysis-meta">
          {result.confidence && <span>{result.confidence} confidence</span>}
          {result.analyzed_by && <span>Analyzed by {result.analyzed_by.replaceAll("_", " ")}</span>}
          {result.cached && <span>Cached result</span>}
          {result.analysis_ms != null && <span>{result.analysis_ms} ms</span>}
          {result.degraded && <span className="degraded-chip">Limited analysis</span>}
        </div>
      )}

      {result.likely_goal && (
        <div className="goal-box">
          <span className="eyebrow">LIKELY GOAL</span>
          <p>{result.likely_goal}</p>
        </div>
      )}

      <div className="findings">
        <h3>What I noticed</h3>
        <div className="finding-list">
          {result.reasons.map((reason, index) => (
            <article className="finding" key={`${reason.type}-${index}`}>
              <span className="finding-dot" />
              <div>
                <h4>{reason.type}</h4>
                <p>{reason.explanation}</p>
                {reason.evidence && <blockquote>“{reason.evidence}”</blockquote>}
                {(reason.severity || reason.contribution != null || reason.source) && (
                  <div className="finding-meta">
                    {reason.severity && <span>{reason.severity}</span>}
                    {reason.contribution != null && <span>+{reason.contribution} points</span>}
                    {reason.source && <span>{reason.source.replaceAll("_", " ")}</span>}
                  </div>
                )}
              </div>
            </article>
          ))}
        </div>
      </div>

      {result.links?.length > 0 && (
        <div className="advanced-section">
          <h3>Link checks</h3>
          <div className="link-list">
            {result.links.map((link, index) => (
              <article className={`link-result verdict-${link.verdict}`} key={`${link.url}-${index}`}>
                <div>
                  <strong>{link.domain || link.url}</strong>
                  <span>{link.verdict}</span>
                </div>
                {link.display_text && <p>Displayed as “{link.display_text}”</p>}
                {link.reasons?.map((reason) => <p key={reason}>{reason}</p>)}
              </article>
            ))}
          </div>
        </div>
      )}

      {result.tone && (
        <div className="advanced-section">
          <h3>Manipulation analysis</h3>
          <p className="tone-summary">{result.tone.summary}</p>
          <div className="tone-list">
            {manipulation.map(([label, value]) => (
              <div className="tone-row" key={label}>
                <span>{label}</span>
                <div><i style={{ width: `${value}%` }} /></div>
                <strong>{value}</strong>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="recommendation">
        <span className="recommendation-icon">
          <ShieldIcon size={19} />
        </span>
        <div>
          <h3>What you should do</h3>
          <p>{result.recommended_action}</p>
        </div>
      </div>

      <button className="secondary-button" type="button" onClick={onReset}>
        Analyze another message
      </button>
    </section>
  );
}

function HistoryPanel({ history, status, onSelect, onRetry }) {
  return (
    <aside className="history-card">
      <div className="history-heading">
        <div>
          <span className="eyebrow">RECENT ACTIVITY</span>
          <h2>Previous checks</h2>
        </div>
        <span className="history-count">{history.length}</span>
      </div>

      {status === "loading" && (
        <div className="history-empty">
          <span className="small-spinner" />
          Loading history...
        </div>
      )}

      {status === "error" && (
        <div className="history-empty">
          <p>History is currently unavailable.</p>
          <button className="text-button" type="button" onClick={onRetry}>Try again</button>
        </div>
      )}

      {status === "ready" && history.length === 0 && (
        <div className="history-empty">
          <ShieldIcon size={28} />
          <p>Your analyzed messages will appear here.</p>
        </div>
      )}

      {history.length > 0 && (
        <div className="history-list">
          {history.map((item) => {
            const tone = getRiskTone(item.risk_score, item.action);

            return (
              <button
                className={`history-item tone-${tone.key}`}
                type="button"
                key={item.id}
                onClick={() => onSelect(item)}
              >
                <span className="history-score">{item.risk_score}</span>
                <span className="history-copy">
                  <strong>{item.category}</strong>
                  <span>{item.summary}</span>
                </span>
                <span className="history-arrow">›</span>
              </button>
            );
          })}
        </div>
      )}
    </aside>
  );
}

function App() {
  const [form, setForm] = useState(initialForm);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [history, setHistory] = useState([]);
  const [historyStatus, setHistoryStatus] = useState("loading");
  const [backendStatus, setBackendStatus] = useState("checking");

  const checkBackend = useCallback(async () => {
    try {
      await request("/health");
      setBackendStatus("connected");
    } catch {
      setBackendStatus("offline");
    }
  }, []);

  const loadHistory = useCallback(async () => {
    try {
      const items = await request("/api/history");
      setHistory(items);
      setHistoryStatus("ready");
      setBackendStatus("connected");
    } catch {
      setHistoryStatus("error");
      setBackendStatus("offline");
    }
  }, []);

  useEffect(() => {
    checkBackend();
    loadHistory();
  }, [checkBackend, loadHistory]);

  useEffect(() => {
    const extensionApi = globalThis.chrome;
    if (!extensionApi?.runtime?.id || !extensionApi.storage?.session) return undefined;

    extensionApi.storage.session.get("selectedAnalysis").then(({ selectedAnalysis }) => {
      if (selectedAnalysis) setResult(selectedAnalysis);
    });

    function handleStorageChange(changes, areaName) {
      if (areaName === "session" && changes.selectedAnalysis?.newValue) {
        setResult(changes.selectedAnalysis.newValue);
      }
    }

    extensionApi.storage.onChanged.addListener(handleStorageChange);
    return () => extensionApi.storage.onChanged.removeListener(handleStorageChange);
  }, []);

  async function handleSubmit(event) {
    event.preventDefault();
    setLoading(true);
    setError("");

    try {
      const links = form.links
        .filter((link) => link.href.trim())
        .map((link) => ({
          href: link.href.trim(),
          text: link.text.trim() || null
        }));

      const analysis = await request("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: form.message.trim(),
          sender: form.sender.trim() || null,
          url: links[0]?.href || null,
          links,
          platform: form.platform || null,
          page_url: form.pageUrl.trim() || null,
          message_id: globalThis.crypto?.randomUUID?.() || `web-${Date.now()}`
        })
      });

      setResult(analysis);
      setBackendStatus("connected");
      loadHistory();
    } catch (requestError) {
      setError(requestError.message);
      if (requestError.message.startsWith("Cannot reach")) setBackendStatus("offline");
    } finally {
      setLoading(false);
    }
  }

  function resetAnalyzer() {
    setResult(null);
    setError("");
    setForm(initialForm);
  }

  function selectHistory(item) {
    setResult(item);
    setError("");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async function switchToBasicMode() {
    if (!IS_EXTENSION) {
      window.location.href = "/popup.html";
      return;
    }

    try {
      const [tab] = await globalThis.chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) throw new Error("No active tab found.");

      const response = await globalThis.chrome.runtime.sendMessage({
        type: "SCAM_SHIELD_SWITCH_TO_BASIC",
        windowId: tab.windowId
      });

      if (!response?.ok) throw new Error(response?.error || "Mode switch failed.");
    } catch {
      setError("Close this panel, then click the Scam Shield toolbar icon to open Basic mode.");
    }
  }

  return (
    <div className={`app-shell ${IS_EXTENSION ? "extension-shell" : ""}`}>
      <header className="site-header">
        <div className="brand" aria-label="Scam Shield">
          <span className="brand-mark">
            <ShieldIcon size={25} />
          </span>
          <span>
            <strong>Scam Shield</strong>
            <small>Advanced mode</small>
          </span>
        </div>

        <div className="header-actions">
          <span className={`status-pill status-${backendStatus}`}>
            <span />
            {backendStatus === "connected"
              ? "Backend connected"
              : backendStatus === "offline"
                ? "Backend offline"
                : "Checking backend"}
          </span>
          <div className="mode-switch" aria-label="Analysis mode">
            <button type="button" onClick={switchToBasicMode}>Basic</button>
            <span className="active-mode">Advanced</span>
          </div>
        </div>
      </header>

      <main className="main-content">
        <div className="hero-copy">
          <span className="hero-badge">
            <ShieldIcon size={15} />
            Advanced analysis
          </span>
          <h1>Think before you click.</h1>
          <p>
            Understand suspicious messages before they become a problem. Get a
            clear risk score, the warning signs, and your safest next step.
          </p>
        </div>

        {error && (
          <div className="error-banner" role="alert">
            <span>!</span>
            <div>
              <strong>Analysis unavailable</strong>
              <p>{error}</p>
            </div>
            <button type="button" onClick={() => setError("")} aria-label="Dismiss error">
              ×
            </button>
          </div>
        )}

        <div className="dashboard-grid">
          {result ? (
            <ResultCard result={result} onReset={resetAnalyzer} />
          ) : (
            <AnalyzerForm
              form={form}
              setForm={setForm}
              onSubmit={handleSubmit}
              loading={loading}
            />
          )}

          <HistoryPanel
            history={history}
            status={historyStatus}
            onSelect={selectHistory}
            onRetry={loadHistory}
          />
        </div>
      </main>

      <footer>
        Scam Shield provides guidance, not a guarantee. Never share passwords or
        verification codes.
      </footer>
    </div>
  );
}

export default App;
