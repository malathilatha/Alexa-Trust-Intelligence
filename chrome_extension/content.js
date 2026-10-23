// Injects one floating button into Gmail. When an email is open, clicking it
// stages the EXACT request that would be sent (sender + subject + body) and
// shows a Send/Cancel step before anything is checked — same "nothing runs
// until you hit send" rule as voice_demo.html, just for a real open email
// instead of a canned scenario.

const sessionId = crypto.randomUUID();

function getOpenEmail() {
  // Gmail's own class names (not stable API, but the standard way every
  // Gmail extension reads an open message's DOM today).
  const subjectEl = document.querySelector("h2.hP");
  const senderEls = document.querySelectorAll("span.gD");
  const bodyEls = document.querySelectorAll("div.a3s.aiL");

  if (!subjectEl || senderEls.length === 0 || bodyEls.length === 0) return null;

  const subject = subjectEl.textContent.trim();
  const senderEl = senderEls[senderEls.length - 1];
  const senderName = senderEl.textContent.trim();
  const senderEmail = senderEl.getAttribute("email") || "";
  const bodyEl = bodyEls[bodyEls.length - 1];
  const body = bodyEl.innerText.trim().slice(0, 1000);

  return { subject, senderName, senderEmail, body };
}

function buildFreeformText(email) {
  const who = email.senderEmail ? `${email.senderName} <${email.senderEmail}>` : email.senderName;
  return `Email from ${who}, subject "${email.subject}": ${email.body}`;
}

// ---------- floating button + panel ----------

const fab = document.createElement("button");
fab.id = "ti-fab";
fab.textContent = "🛡️ Check with Trust Intelligence";
document.body.appendChild(fab);

const panel = document.createElement("div");
panel.id = "ti-panel";
panel.innerHTML = `
  <div class="ti-head">
    <span>Trust Intelligence</span>
    <button class="ti-close" id="ti-close">✕</button>
  </div>
  <div class="ti-body" id="ti-body"></div>
`;
document.body.appendChild(panel);

document.getElementById("ti-close").onclick = () => panel.classList.remove("open");

function renderStaged(email) {
  const text = buildFreeformText(email);
  document.getElementById("ti-body").innerHTML = `
    <div class="ti-label">What would be sent</div>
    <div class="ti-quote">${escapeHtml(text)}</div>
    <div class="ti-actions">
      <button class="ti-btn-primary" id="ti-go">Send to Alexa+ ▶</button>
      <button class="ti-btn-secondary" id="ti-cancel">Cancel</button>
    </div>
  `;
  document.getElementById("ti-cancel").onclick = () => panel.classList.remove("open");
  document.getElementById("ti-go").onclick = () => runCheck(text);
  panel.classList.add("open");
}

function renderSpinner() {
  document.getElementById("ti-body").innerHTML = `<div class="ti-spinner">Checking with Alexa Trust Intelligence…</div>`;
}

function renderError(message) {
  document.getElementById("ti-body").innerHTML = `<div class="ti-error">${escapeHtml(message)}</div>`;
}

function renderResult(requestText, data) {
  if (data.needs_more_info) {
    document.getElementById("ti-body").innerHTML = `
      <div class="ti-label">Request sent</div>
      <div class="ti-quote">${escapeHtml(requestText)}</div>
      <div class="ti-card">
        <div class="ti-decision REVIEW">MORE INFO NEEDED</div>
        <ul class="ti-reasons">${(data.card?.top_reasons || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>
      </div>
    `;
    return;
  }

  const card = data.card || {};
  const decision = data.final_decision || data.check?.decision || data.decision || "—";
  const risk = data.check?.risk_score ?? data.risk_score;
  const reasons = card.top_reasons || [];
  const action = card.action || data.spoken || "";

  document.getElementById("ti-body").innerHTML = `
    <div class="ti-label">Request sent</div>
    <div class="ti-quote">${escapeHtml(requestText)}</div>
    <div class="ti-card ${decision}">
      <span class="ti-decision ${decision}">${escapeHtml(card.title || decision)}</span>
      ${risk !== undefined ? `<div class="ti-risk">Risk score ${risk}/100</div>` : ""}
      <ul class="ti-reasons">${reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>
      ${action ? `<div class="ti-action"><b>Recommended action</b>${escapeHtml(action)}</div>` : ""}
    </div>
  `;
}

function runCheck(text) {
  renderSpinner();
  chrome.runtime.sendMessage({ type: "TRUST_CHECK", text, sessionId }, (resp) => {
    if (!resp || !resp.ok) {
      renderError(resp?.error || "No response from the extension background worker.");
      return;
    }
    renderResult(text, resp.data);
  });
}

function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

fab.onclick = () => {
  const email = getOpenEmail();
  if (!email) {
    document.getElementById("ti-body").innerHTML = `<div class="ti-error">Open an email first, then click this button.</div>`;
    panel.classList.add("open");
    return;
  }
  renderStaged(email);
};
