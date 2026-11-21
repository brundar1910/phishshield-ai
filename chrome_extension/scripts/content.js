// Content Script for PhishShield AI
// Performs DOM analysis and injects security warnings on suspicious/phishing sites

(function () {
  const currentUrl = window.location.href;
  if (
    currentUrl.startsWith("chrome://") ||
    currentUrl.startsWith("edge://") ||
    currentUrl.startsWith("http://localhost") ||
    currentUrl.startsWith("http://127.0.0.1")
  ) {
    return;
  }

  // 1. Check for insecure password input fields on HTTP pages
  const isHttp = window.location.protocol === "http:";
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  if (isHttp && passwordInputs.length > 0) {
    showInsecurePasswordWarning();
  }

  // 2. Query backend for real-time URL classification
  fetch("http://localhost:8000/api/scan/url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: currentUrl, include_features: false }),
  })
    .then((res) => (res.ok ? res.json() : null))
    .then((data) => {
      if (!data) return;
      const verdict = data.verdict || data.threat_level;
      if (verdict === "CRITICAL" || verdict === "HIGH") {
        showPhishingWarningBanner(data);
      }
    })
    .catch(() => {
      // Backend offline
    });

  function showPhishingWarningBanner(data) {
    if (document.getElementById("phishshield-warning-banner")) return;

    const banner = document.createElement("div");
    banner.id = "phishshield-warning-banner";
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      background: linear-gradient(90deg, #991b1b, #dc2626);
      color: #ffffff;
      padding: 14px 20px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 13px;
      font-weight: 600;
      z-index: 2147483647;
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: 0 4px 14px rgba(0,0,0,0.5);
      border-bottom: 2px solid #f87171;
    `;

    const flagsText = (data.heuristic_flags || []).slice(0, 2).join("; ");

    banner.innerHTML = `
      <div style="display: flex; align-items: center; gap: 12px;">
        <span style="font-size: 22px;">🛡️⚠️</span>
        <div>
          <div style="font-size: 14px; font-weight: 700; letter-spacing: 0.3px;">
            PHISHSHIELD SECURITY ALERT: ${data.verdict} THREAT DETECTED (Risk Score: ${data.risk_score}/100)
          </div>
          <div style="font-size: 12px; font-weight: 400; opacity: 0.95; margin-top: 2px;">
            ${data.explanation || "This destination exhibits characteristics of a fraudulent site. Do not enter credentials."}
            ${flagsText ? ` <em style="opacity: 0.85;">[${flagsText}]</em>` : ""}
          </div>
        </div>
      </div>
      <div style="display: flex; gap: 8px;">
        <button id="phishshield-leave-btn" style="
          background: #ffffff;
          color: #991b1b;
          border: none;
          padding: 6px 14px;
          border-radius: 4px;
          cursor: pointer;
          font-weight: 700;
          font-size: 12px;
        ">Leave Site</button>
        <button id="phishshield-dismiss" style="
          background: rgba(0,0,0,0.3);
          border: 1px solid rgba(255,255,255,0.4);
          color: white;
          padding: 6px 12px;
          border-radius: 4px;
          cursor: pointer;
          font-weight: 600;
          font-size: 12px;
        ">Dismiss</button>
      </div>
    `;

    document.body.prepend(banner);

    document.getElementById("phishshield-leave-btn").addEventListener("click", () => {
      window.location.href = "about:blank";
    });

    document.getElementById("phishshield-dismiss").addEventListener("click", () => {
      banner.remove();
    });
  }

  function showInsecurePasswordWarning() {
    if (document.getElementById("phishshield-insecure-pw-banner")) return;
    const banner = document.createElement("div");
    banner.id = "phishshield-insecure-pw-banner";
    banner.style.cssText = `
      position: fixed;
      bottom: 10px;
      right: 10px;
      max-width: 380px;
      background: #78350f;
      color: #fef3c7;
      padding: 12px 16px;
      font-family: sans-serif;
      font-size: 12px;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.4);
      z-index: 2147483647;
      border-left: 4px solid #f59e0b;
    `;
    banner.innerHTML = `
      <strong>⚠️ Insecure Login Form:</strong> Password input detected over unencrypted HTTP. Submitting credentials here risks credential theft.
    `;
    document.body.appendChild(banner);
  }
})();
