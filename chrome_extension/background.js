// Runs the actual network call to voice_bridge.py. Done here, not in the
// content script, so the request isn't subject to Gmail's page-level CORS —
// a background service worker with host_permissions can fetch cross-origin.

const BRIDGE_URL = "http://127.0.0.1:8010/api/run";

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type !== "TRUST_CHECK") return;

  fetch(BRIDGE_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      mode: "freeform",
      text: msg.text,
      session_id: msg.sessionId,
    }),
  })
    .then((r) => r.json())
    .then((data) => sendResponse({ ok: true, data }))
    .catch((err) =>
      sendResponse({
        ok: false,
        error:
          "Could not reach voice_bridge.py on 127.0.0.1:8010. Is it running? (" +
          err.message +
          ")",
      })
    );

  return true; // keep the message channel open for the async response
});
