// Background Service Worker for PhishShield AI
// Automatically inspects tab URLs against local FastAPI backend

const API_ENDPOINT = "http://localhost:8000/api/scan/url";

chrome.runtime.onInstalled.addListener(() => {
  console.log("[PhishShield AI] Extension installed and active.");
});

// Update badge when tabs navigate
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && !tab.url.startsWith("chrome://") && !tab.url.startsWith("edge://")) {
    scanTabUrl(tabId, tab.url);
  }
});

async function scanTabUrl(tabId, url) {
  try {
    const response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, include_features: false }),
    });

    if (!response.ok) {
      chrome.action.setBadgeText({ tabId, text: "" });
      return;
    }

    const data = await response.json();
    const verdict = data.verdict || data.threat_level;

    if (verdict === "CRITICAL" || verdict === "HIGH") {
      chrome.action.setBadgeText({ tabId, text: "!" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#EF4444" });
    } else if (verdict === "MEDIUM") {
      chrome.action.setBadgeText({ tabId, text: "?" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#F59E0B" });
    } else {
      chrome.action.setBadgeText({ tabId, text: "✓" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#10B981" });
    }
  } catch (err) {
    // Backend offline or unreachable
    chrome.action.setBadgeText({ tabId, text: "" });
  }
}
