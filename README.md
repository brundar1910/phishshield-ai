# 🛡️ PhishShield AI — AI & ML-Based Phishing Detection and Browser Protection System

PhishShield AI is an enterprise-grade cybersecurity system designed to identify and neutralize phishing threats across multiple attack vectors in real time. It combines lexical and structural URL machine learning classification, NLP email intent and urgency analysis, DOM/HTML inspection, and OCR screenshot analysis into a single risk-scoring pipeline.

---

## 🏛️ System Architecture

```text
+---------------------------------------------------------------------------------------+
|                                    USER CLIENTS                                       |
|  +--------------------------------+   +--------------------------------------------+  |
|  | Chrome Extension (Manifest V3) |   | Interactive Dashboard (frontend/Dashboard) |  |
|  +---------------+----------------+   +---------------------+----------------------+  |
+------------------|------------------------------------------|-------------------------+
                   |                                          |
                   | HTTP / JSON REST API                     |
                   v                                          v
+---------------------------------------------------------------------------------------+
|                                  FASTAPI BACKEND API                                 |
|  +---------------------------------------------------------------------------------+  |
|  | Endpoints: /api/scan/url, /api/scan/email, /api/scan/html, /api/scan/image       |  |
|  |            /api/history,  /api/stats,      /api/metrics,   /api/health          |  |
|  +---------------------------------------+-----------------------------------------+  |
+------------------------------------------|--------------------------------------------+
                                           v
+---------------------------------------------------------------------------------------+
|                        UNIFIED MULTI-MODAL DETECTION ENGINE                           |
|                                                                                       |
|  +-----------------------+ +-----------------------+ +-----------------------------+  |
|  |   URL ML Classifier   | |   NLP Email Analyzer  | |     HTML DOM Inspector      |  |
|  | - 29 lexical features | | - Urgency & threats   | | - Form submission targets   |  |
|  | - Logistic Regression | | - Credential prompts  | | - Hidden zero-dim iframes   |  |
|  | - Random Forest & XGB | | - Embedded link scans | | - Anchor text discrepancy   |  |
|  +-----------------------+ +-----------------------+ +-----------------------------+  |
|                             +--------------------+                                    |
|                             |  OCR Image Scanner |                                    |
|                             | - Form aspect ratio|                                    |
|                             | - Color variance   |                                    |
|                             +--------------------+                                    |
+------------------------------------------+--------------------------------------------+
                                           |
                   +-----------------------+-----------------------+
                   v                                               v
+------------------------------------+   +----------------------------------------------+
|     SQLITE AUDIT PERSISTENCE       |   |               SAVED ML ARTIFACTS             |
| - scan_logs (Type, Target, Score)  |   | - best_model.joblib (Champion Model)         |
| - Aggregated real-time metrics     |   | - scaler.joblib (StandardScaler)             |
| - Heuristic threat frequency       |   | - metrics.json (Genuine 20% test evaluation) |
+------------------------------------+   +----------------------------------------------+
```

---

## ✨ Features

- **Machine Learning URL Classifier:**
  - Extracts 29 structural, lexical, domain, and entropy features (IP hostnames, URL shorteners, punycode, high-risk TLDs, keyword presence, subdomain count, Shannon entropy).
  - Production-ready models trained with strict train/test isolation to prevent data leakage: **Logistic Regression** (Champion), **Random Forest**, and **XGBoost**.
  - Evaluated on a 300-URL isolated test split with genuine, disk-persisted metrics in `ml/saved_models/metrics.json`.
- **NLP Email & Text Analyzer:**
  - Detects social engineering patterns, high-pressure urgency triggers ("within 24 hours", "action required immediately"), and credential harvesting demands.
  - Recursively extracts and inspects all embedded URLs.
- **HTML / DOM Inspector:**
  - Inspects page markup for unencrypted password forms over HTTP, external form action targets, hidden zero-dimension iframes, and deceptive hyperlink text mismatches.
- **Visual & OCR Screenshot Scanner:**
  - Analyzes webpage screenshot dimensions, modal box aspect ratios, and color variance using OpenCV and PIL to detect credential overlay phishing cards.
- **Unified Risk-Scoring Pipeline:**
  - Calibrated 0–100 risk score and 4 standard verdicts: `LOW` (0–29), `MEDIUM` (30–59), `HIGH` (60–84), and `CRITICAL` (85–100) accompanied by human-readable explanations.
- **FastAPI Backend:**
  - Asynchronous, clean REST endpoints with Pydantic request/response validation and SQLite audit logging.
- **Interactive Web Dashboard:**
  - Standalone dark-mode dashboard (`Dashboard.html`) with interactive scanners for URLs, emails, HTML DOM, screenshots, live database audit history, and ML performance metrics.
- **Chrome Extension (Manifest V3):**
  - Background service worker scans active tabs automatically, displays dynamic colored risk badges (`✓`, `?`, `!`), and injects warning banner overlays on high-risk sites.

---

## 🚀 Quick Setup & Usage

### Prerequisites
- Python 3.10+ installed and added to `PATH`.

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. One-Click Launch (`start.bat`)
On Windows, simply double-click `start.bat` or run:
```cmd
start.bat
```
This automatically sets the `PYTHONPATH`, launches the Uvicorn server on `http://127.0.0.1:8000`, and opens the **PhishShield AI Dashboard** in your default web browser (`http://localhost:8000/Dashboard.html`).

### 3. Manual Server Launch
Alternatively, you can start the backend manually:
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
- **Web Dashboard:** [http://localhost:8000/Dashboard.html](http://localhost:8000/Dashboard.html)
- **Interactive API Docs (Swagger UI):** [http://localhost:8000/docs](http://localhost:8000/docs)

### 4. Chrome Extension Installation (Manifest V3)
1. Open Google Chrome, Brave, or Edge and go to `chrome://extensions/`.
2. Toggle on **Developer mode** in the top-right corner.
3. Click **Load unpacked** and select the `chrome_extension/` directory.
4. The PhishShield AI icon will appear in your extensions bar, automatically protecting your browsing sessions.

---

## 🧪 Testing

The test suite validates URL feature extraction, trained model predictions, detection heuristics, and all REST API endpoints.

To run the complete test suite:
```bash
python -m pytest backend/tests/ -v
```
