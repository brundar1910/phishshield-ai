/**
 * Comprehensive API Client Service for Phishing Detection Platform.
 */

const BASE_URL = "http://localhost:8000/api";

export async function scanURL(url, includeFeatures = true) {
  const response = await fetch(`${BASE_URL}/scan/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, include_features: includeFeatures })
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "Scan failed" }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }
  return response.json();
}

export async function scanEmail(subject, body, sender = "") {
  const response = await fetch(`${BASE_URL}/scan/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ subject, body, sender })
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "Email scan failed" }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }
  return response.json();
}

export async function scanHTML(html_content, base_url = "") {
  const response = await fetch(`${BASE_URL}/scan/html`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ html_content, base_url })
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "HTML scan failed" }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }
  return response.json();
}

export async function scanImage(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${BASE_URL}/scan/image`, {
    method: "POST",
    body: formData
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "Image scan failed" }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }
  return response.json();
}

export async function fetchScanHistory(limit = 50, scan_type = null) {
  let url = `${BASE_URL}/history?limit=${limit}`;
  if (scan_type) url += `&scan_type=${encodeURIComponent(scan_type)}`;
  const response = await fetch(url);
  if (!response.ok) throw new Error("Failed to load scan history");
  return response.json();
}

export async function fetchStats() {
  const response = await fetch(`${BASE_URL}/stats`);
  if (!response.ok) throw new Error("Failed to load security statistics");
  return response.json();
}

export async function fetchMetrics() {
  const response = await fetch(`${BASE_URL}/metrics`);
  if (!response.ok) throw new Error("Failed to load model metrics");
  return response.json();
}

export async function fetchHealth() {
  const response = await fetch(`${BASE_URL}/health`);
  if (!response.ok) throw new Error("Backend offline");
  return response.json();
}
