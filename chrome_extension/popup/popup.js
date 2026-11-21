const API_SCAN_ENDPOINT = "http://localhost:8000/api/scan/url";

document.addEventListener("DOMContentLoaded", () => {
  const urlDisplay = document.getElementById("url-display");
  const verdictBadge = document.getElementById("verdict-badge");
  const riskScoreText = document.getElementById("risk-score-text");
  const threatProgress = document.getElementById("threat-progress");
  const explanationText = document.getElementById("explanation-text");
  const flagsList = document.getElementById("flags-list");
  const featuresGrid = document.getElementById("features-grid");
  const statusDot = document.getElementById("status-dot");
  const rescanBtn = document.getElementById("rescan-btn");
  const manualInput = document.getElementById("manual-url-input");
  const manualScanBtn = document.getElementById("manual-scan-btn");

  let activeUrl = "";

  function updateUI(res) {
    const verdict = res.verdict || res.threat_level || "LOW";
    const score = typeof res.risk_score === "number" ? res.risk_score : Math.round((res.confidence || 0) * 100);

    riskScoreText.textContent = `${score}/100`;
    threatProgress.style.width = `${score}%`;

    verdictBadge.className = "badge";
    if (verdict === "CRITICAL") {
      verdictBadge.classList.add("critical");
      verdictBadge.textContent = "CRITICAL THREAT";
      threatProgress.style.backgroundColor = "#ef4444";
    } else if (verdict === "HIGH") {
      verdictBadge.classList.add("high");
      verdictBadge.textContent = "HIGH RISK";
      threatProgress.style.backgroundColor = "#f87171";
    } else if (verdict === "MEDIUM") {
      verdictBadge.classList.add("medium");
      verdictBadge.textContent = "MEDIUM RISK";
      threatProgress.style.backgroundColor = "#f59e0b";
    } else {
      verdictBadge.classList.add("low");
      verdictBadge.textContent = "LOW RISK (SAFE)";
      threatProgress.style.backgroundColor = "#10b981";
    }

    explanationText.textContent = res.explanation || "No suspicious indicators identified.";

    flagsList.innerHTML = "";
    if (!res.heuristic_flags || res.heuristic_flags.length === 0) {
      flagsList.innerHTML = `<li class="flag-item" style="color: #34d399;">✓ No anomalous security signals detected</li>`;
    } else {
      res.heuristic_flags.forEach(f => {
        const li = document.createElement("li");
        li.className = "flag-item";
        li.textContent = f;
        flagsList.appendChild(li);
      });
    }

    featuresGrid.innerHTML = "";
    if (res.features) {
      Object.entries(res.features).forEach(([k, v]) => {
        const row = document.createElement("div");
        row.style.display = "flex";
        row.style.justifyContent = "space-between";
        row.innerHTML = `<span style="color: #7dd3fc;">${k}</span><span>${v}</span>`;
        featuresGrid.appendChild(row);
      });
    } else {
      featuresGrid.innerHTML = "<span>Features omitted</span>";
    }
  }

  async function performScan(url) {
    if (!url || url.startsWith("chrome://") || url.startsWith("edge://")) {
      urlDisplay.textContent = url || "Internal Browser Page";
      verdictBadge.className = "badge low";
      verdictBadge.textContent = "INTERNAL";
      riskScoreText.textContent = "0/100";
      threatProgress.style.width = "0%";
      explanationText.textContent = "Internal browser page (safe by default).";
      flagsList.innerHTML = `<li class="flag-item">Internal system origin</li>`;
      return;
    }

    urlDisplay.textContent = url;
    verdictBadge.className = "badge";
    verdictBadge.textContent = "SCANNING...";
    explanationText.textContent = "Communicating with AI detection engine...";

    try {
      const response = await fetch(API_SCAN_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, include_features: true })
      });

      if (!response.ok) {
        throw new Error(`API returned HTTP ${response.status}`);
      }

      const data = await response.json();
      statusDot.className = "dot green";
      statusDot.title = "Backend Online";
      updateUI(data);
    } catch (err) {
      statusDot.className = "dot red";
      statusDot.title = "Backend Offline";
      verdictBadge.className = "badge medium";
      verdictBadge.textContent = "OFFLINE";
      riskScoreText.textContent = "N/A";
      explanationText.textContent = `Backend connection failed: ${err.message}. Start FastAPI on localhost:8000.`;
      flagsList.innerHTML = `<li class="flag-item">Cannot reach detection service</li>`;
    }
  }

  // Obtain active tab
  if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        activeUrl = tabs[0].url;
        performScan(activeUrl);
      } else {
        urlDisplay.textContent = "No active URL found";
      }
    });
  } else {
    // Standalone fallback
    activeUrl = "http://192.168.1.100/paypal/login.php?verification=token";
    performScan(activeUrl);
  }

  rescanBtn.addEventListener("click", () => {
    if (activeUrl) performScan(activeUrl);
  });

  manualScanBtn.addEventListener("click", () => {
    const custom = manualInput.value.trim();
    if (custom) {
      activeUrl = custom;
      performScan(custom);
    }
  });
});
