import { useCallback, useEffect, useState } from "react";

const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

const initialForm = {
  message: "",
  sender: "",
  url: ""
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

function getRiskTone(score) {
  if (score <= 20) return { key: "low", label: "Low risk" };
  if (score <= 60) return { key: "suspicious", label: "Suspicious" };
  if (score <= 80) return { key: "high", label: "High risk" };
  return { key: "extreme", label: "Extremely high risk" };
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
    throw new Error(`Cannot reach the backend at ${API_URL}. Make sure FastAPI is running.`);
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
              placeholder="e.g. My Bank"
            />
          </label>
          <label>
            Included link <span>optional</span>
            <input
              name="url"
              value={form.url}
              onChange={updateField}
              type="url"
              placeholder="https://..."
            />
          </label>
        </div>

        <button className="primary-button" type="submit" disabled={loading}>
          {loading ? <span className="button-spinner" /> : <ShieldIcon size={19} />}
          {loading ? "Inspecting message..." : "Analyze message"}
        </button>
      </form>
    </section>
  );
}

function ResultCard({ result, onReset }) {
  const tone = getRiskTone(result.risk_score);

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
        <p>{result.summary}</p>
      </div>

      <div className="findings">
        <h3>What I noticed</h3>
        <div className="finding-list">
          {result.reasons.map((reason, index) => (
            <article className="finding" key={`${reason.type}-${index}`}>
              <span className="finding-dot" />
              <div>
                <h4>{reason.type}</h4>
                <p>{reason.explanation}</p>
              </div>
            </article>
          ))}
        </div>
      </div>

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

function HistoryPanel({ history, status, onSelect }) {
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
        <div className="history-empty">History is currently unavailable.</div>
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
            const tone = getRiskTone(item.risk_score);

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

  const loadHistory = useCallback(async () => {
    try {
      const items = await request("/api/history");
      setHistory(items);
      setHistoryStatus("ready");
    } catch {
      setHistoryStatus("error");
    }
  }, []);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

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
      const analysis = await request("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: form.message.trim(),
          sender: form.sender.trim() || null,
          url: form.url.trim() || null,
          platform: "web",
          page_url: window.location.href
        })
      });

      setResult(analysis);
      loadHistory();
    } catch (requestError) {
      setError(requestError.message);
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

  return (
    <div className="app-shell">
      <header className="site-header">
        <div className="brand" aria-label="Scam Shield">
          <span className="brand-mark">
            <ShieldIcon size={25} />
          </span>
          <span>
            <strong>Scam Shield</strong>
            <small>Your message guard</small>
          </span>
        </div>

        <div className="status-pill">
          <span />
          AI-powered protection
        </div>
      </header>

      <main className="main-content">
        <div className="hero-copy">
          <span className="hero-badge">
            <ShieldIcon size={15} />
            The Guard is watching
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
