# Phishing & Benign URL Datasets

This directory houses dataset resources and metadata for training the URL-based Phishing Detection ML models.

## Sources & Provenance

### 1. PhishTank
- **URL**: [https://phishtank.org](https://phishtank.org)
- **Description**: A collaborative clearing house for data and information about phishing on the Internet. Provides verified phishing URLs via automated and community-vetted feeds (`verified_online.csv`).
- **Features Captured**: Live phishing URLs targeting banking, social media, crypto, cloud credentials, and e-commerce.

### 2. UCI Machine Learning Repository: Phishing Websites Dataset
- **URL**: [https://archive.ics.uci.edu/dataset/327/phishing+websites](https://archive.ics.uci.edu/dataset/327/phishing+websites)
- **Description**: Benchmark dataset analyzing URL, address bar, anomalies, and HTML/JavaScript properties.
- **Reference**: Mohammad, R. M., Thabtah, F., & McCluskey, L. (2015). Predicting phishing websites based on self-structuring neural network. *Neural Computing and Applications*.

### 3. Kaggle Phishing Datasets
- **Malicious & Benign URLs Dataset**: Aggregated datasets curated by cybersecurity researchers containing verified Alexa/Tranco top sites paired with active phishing attacks (e.g. `sid321/malicious-urls-dataset`, `taruntiwarihp/phishing-site-urls`).

## Included Local Dataset: `urls_dataset.csv`

To ensure local reproducibility without requiring multi-gigabyte downloads or active internet connections, this repository includes a curated, balanced dataset of **1,400+ distinct URLs**:
- **700 Benign URLs (Label: 0)**: High-reputation domains (Tranco/Alexa top 1,000, .gov, .edu, open-source repos, cloud document subpaths, multi-level paths).
- **700 Phishing URLs (Label: 1)**: Authentic phishing attack vectors covering:
  - IP-based URLs (e.g., `http://192.168.1.100/paypal/login.php`)
  - Subdomain abuse & brand spoofing (e.g., `http://netflix.account-verification.login.xyz/auth`)
  - URL shorteners hiding destination payloads (e.g., `bit.ly`, `tinyurl.com`, `is.gd`)
  - High-risk TLD abuse (`.top`, `.work`, `.click`, `.buzz`, `.xyz`, etc.)
  - Obfuscated credentials (`http://secure-login.com@phish-site.cc/confirm`)
  - Deep path deceptive keywords (`update-billing-info`, `re-verify-account`, `secure-banking-token`)

## Leakage Prevention Protocol
The dataset loader enforces:
1. Strict URL deduplication prior to feature extraction.
2. Stratified 80/20 train/test splitting with fixed random seeds (`random_state=42`).
3. Standard Scaler fit **strictly** on the training split, and only transforming the test split.
