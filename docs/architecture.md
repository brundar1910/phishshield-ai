# Phishing Detection System Architecture

## System Components

```mermaid
flowchart TD
    Client[Web Browser / User] -->|Browsing Traffic| Ext[Chrome Extension Manifest V3]
    Client -->|Manual Inspection| WebUI[Modern Dashboard & Streamlit App]
    Ext -->|HTTP POST /api/scan| API[FastAPI Backend Gateway]
    WebUI -->|HTTP GET /api/metrics| API
    WebUI -->|HTTP POST /api/scan| API

    subgraph Backend Core
        API --> DetectionEngine[Ensemble Detection Engine]
        DetectionEngine --> Extractor[URL Feature Extractor - 29 Features]
        DetectionEngine --> Heuristics[Heuristic Security Evaluator]
        DetectionEngine --> MLInference[ML Classifier Pipeline]
        
        HTML[HTML Analyzer] -.-> DetectionEngine
        NLP[NLP Content Analyzer] -.-> DetectionEngine
        OCR[Visual / OCR Analyzer] -.-> DetectionEngine
    end

    subgraph ML Subsystem
        Dataset[1,500 Balanced URLs] --> Preprocessor[Dataset Preprocessor]
        Preprocessor --> Scaler[StandardScaler - Train Only]
        Preprocessor --> Train[Model Trainer]
        Train --> LogReg[Logistic Regression]
        Train --> RF[Random Forest]
        Train --> XGB[XGBoost]
        Train --> Evaluator[Model Evaluator]
        Evaluator --> Metrics[metrics.json & Artifacts]
    end

    subgraph Storage
        API --> SQLite[(SQLite Audit DB)]
    end

    MLInference --> Scaler
    MLInference --> LogReg
```

## Security Design & Data Integrity
1. **Data Leakage Prevention**: `StandardScaler` is strictly fit on the training partition ($N=1,200$) and never exposed to the test partition ($N=300$).
2. **Deduplication**: Strict hash and string deduplication runs before feature vector extraction.
3. **Multi-Layer Defense**: Heuristics catch immediate known attack signatures (such as raw IP hosts and embedded TLD subdomains) while ML identifies subtle multi-dimensional statistical patterns.
4. **Observable Metrics**: All evaluation scores (accuracy, precision, recall, F1, ROC-AUC, confusion matrices) are calculated dynamically on the test set and saved directly to `ml/saved_models/metrics.json`.
